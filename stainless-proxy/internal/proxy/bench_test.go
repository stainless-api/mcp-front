package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stainless-api/stainless-proxy/internal/jwe"
	"github.com/stainless-api/stainless-proxy/internal/revocation"
)

type traceCollector struct {
	mu     sync.Mutex
	traces []RequestTrace
}

func (c *traceCollector) collect(t RequestTrace) {
	c.mu.Lock()
	c.traces = append(c.traces, t)
	c.mu.Unlock()
}

func (c *traceCollector) reset() {
	c.mu.Lock()
	c.traces = c.traces[:0]
	c.mu.Unlock()
}

type benchHarness struct {
	proxy   *Proxy
	enc     *jwe.Encryptor
	backend *httptest.Server
	host    string
	col     *traceCollector
}

func suppressLogs(tb testing.TB) {
	tb.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	tb.Cleanup(func() { slog.SetDefault(prev) })
}

func newBenchHarness(tb testing.TB, handler http.Handler) *benchHarness {
	tb.Helper()
	suppressLogs(tb)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	kid := "bench-key"
	enc := jwe.NewEncryptor(&key.PublicKey, kid)
	dec := jwe.NewMultiKeyDecryptor([]jwe.KeyEntry{{KID: kid, PrivateKey: key}})
	dl := revocation.NewDenyList()
	p := New(dec, dl)

	col := &traceCollector{}
	p.OnTrace = col.collect

	backend := httptest.NewTLSServer(handler)
	p.client = backend.Client()
	host := strings.TrimPrefix(backend.URL, "https://")

	tb.Cleanup(backend.Close)

	return &benchHarness{proxy: p, enc: enc, backend: backend, host: host, col: col}
}

func (h *benchHarness) mint(tb testing.TB, creds []jwe.Credential) string {
	tb.Helper()
	payload := jwe.Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: []string{h.host},
		Credentials:  creds,
	}
	token, err := h.enc.Encrypt(payload)
	if err != nil {
		tb.Fatal(err)
	}
	return token
}

// =============================================================================
// Benchmark: JWE encrypt + decrypt cycle (crypto overhead in isolation)
// =============================================================================

func BenchmarkJWECrypto(b *testing.B) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc := jwe.NewEncryptor(&key.PublicKey, "bench")
	dec := jwe.NewMultiKeyDecryptor([]jwe.KeyEntry{{KID: "bench", PrivateKey: key}})

	payload := jwe.Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: []string{"api.example.com"},
		Credentials: []jwe.Credential{
			{Header: "DD-API-KEY", Value: "datadog-api-key-12345"},
			{Header: "DD-APPLICATION-KEY", Value: "datadog-app-key-67890"},
		},
	}

	b.Run("encrypt", func(b *testing.B) {
		for b.Loop() {
			_, err := enc.Encrypt(payload)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	token, _ := enc.Encrypt(payload)
	b.Run("decrypt", func(b *testing.B) {
		for b.Loop() {
			_, err := dec.Decrypt(token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("round_trip", func(b *testing.B) {
		for b.Loop() {
			t, _ := enc.Encrypt(payload)
			_, err := dec.Decrypt(t)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// =============================================================================
// Benchmark: End-to-end proxy throughput (sequential)
// Simulates a sandbox making sequential API calls through the proxy.
// =============================================================================

func BenchmarkProxySequential(b *testing.B) {
	h := newBenchHarness(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))

	token := h.mint(b, []jwe.Credential{
		{Header: "DD-API-KEY", Value: "datadog-api-key-12345"},
		{Header: "DD-APPLICATION-KEY", Value: "datadog-app-key-67890"},
	})

	h.col.reset()
	b.ResetTimer()

	for b.Loop() {
		req := httptest.NewRequest("GET", "/https/"+h.host+"/api/v2/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.proxy.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status: %d", w.Code)
		}
	}

	b.StopTimer()
	reportTraces(b, h.col.traces)
}

// =============================================================================
// Benchmark: End-to-end proxy throughput (parallel)
// Simulates multiple sandboxes hitting the proxy concurrently.
// =============================================================================

func BenchmarkProxyParallel(b *testing.B) {
	h := newBenchHarness(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))

	token := h.mint(b, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer real-token"},
	})

	h.col.reset()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/https/"+h.host+"/api/data", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.proxy.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status: %d", w.Code)
			}
		}
	})

	b.StopTimer()
	reportTraces(b, h.col.traces)
}

// =============================================================================
// Benchmark: Proxy with varying payload sizes
// Measures throughput degradation as request/response bodies grow.
// =============================================================================

func BenchmarkProxyPayloadSizes(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"10KB", 10 * 1024},
		{"100KB", 100 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			responseBody := bytes.Repeat([]byte("x"), sz.size)

			h := newBenchHarness(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(responseBody)
			}))

			token := h.mint(b, []jwe.Credential{
				{Header: "Authorization", Value: "Bearer x"},
			})

			requestBody := bytes.Repeat([]byte("y"), sz.size)

			h.col.reset()
			b.ResetTimer()
			b.SetBytes(int64(sz.size) * 2) // request + response

			for b.Loop() {
				req := httptest.NewRequest("POST", "/https/"+h.host+"/api", bytes.NewReader(requestBody))
				req.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				h.proxy.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					b.Fatalf("unexpected status: %d", w.Code)
				}
			}

			b.StopTimer()
			reportTraces(b, h.col.traces)
		})
	}
}

// =============================================================================
// Benchmark: Proxy with varying credential counts
// Measures impact of many credentials in a single JWE.
// =============================================================================

func BenchmarkProxyCredentialCount(b *testing.B) {
	counts := []int{1, 5, 10, 50}

	for _, n := range counts {
		b.Run(fmt.Sprintf("%d_credentials", n), func(b *testing.B) {
			h := newBenchHarness(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			creds := make([]jwe.Credential, n)
			for i := range n {
				creds[i] = jwe.Credential{
					Header: fmt.Sprintf("X-Credential-%d", i),
					Value:  fmt.Sprintf("secret-value-%d-with-some-realistic-length-padding", i),
				}
			}

			token := h.mint(b, creds)

			h.col.reset()
			b.ResetTimer()

			for b.Loop() {
				req := httptest.NewRequest("GET", "/https/"+h.host+"/api", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				h.proxy.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					b.Fatalf("unexpected status: %d", w.Code)
				}
			}

			b.StopTimer()
			reportTraces(b, h.col.traces)
		})
	}
}

// =============================================================================
// Benchmark: Deny-list impact under load
// Measures overhead when the deny-list has many entries.
// =============================================================================

func BenchmarkDenyListOverhead(b *testing.B) {
	entryCounts := []int{0, 100, 10_000, 100_000}

	for _, n := range entryCounts {
		b.Run(fmt.Sprintf("%d_entries", n), func(b *testing.B) {
			h := newBenchHarness(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			for i := range n {
				h.proxy.denyList.Add(fmt.Sprintf("fake-hash-%d", i), time.Now().Add(time.Hour))
			}

			token := h.mint(b, []jwe.Credential{
				{Header: "Authorization", Value: "Bearer x"},
			})

			h.col.reset()
			b.ResetTimer()

			for b.Loop() {
				req := httptest.NewRequest("GET", "/https/"+h.host+"/api", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				h.proxy.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					b.Fatalf("unexpected status: %d", w.Code)
				}
			}

			b.StopTimer()
			reportTraces(b, h.col.traces)
		})
	}
}

// =============================================================================
// Benchmark: Slow backend (realistic network latency simulation)
// Measures proxy overhead when the bottleneck is upstream latency.
// =============================================================================

func BenchmarkProxyWithLatency(b *testing.B) {
	latencies := []time.Duration{
		0,
		1 * time.Millisecond,
		10 * time.Millisecond,
		50 * time.Millisecond,
	}

	for _, lat := range latencies {
		name := "0ms"
		if lat > 0 {
			name = lat.String()
		}
		b.Run(name, func(b *testing.B) {
			h := newBenchHarness(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if lat > 0 {
					time.Sleep(lat)
				}
				w.Write([]byte(`{"ok":true}`))
			}))

			token := h.mint(b, []jwe.Credential{
				{Header: "Authorization", Value: "Bearer x"},
			})

			h.col.reset()
			b.ResetTimer()

			for b.Loop() {
				req := httptest.NewRequest("GET", "/https/"+h.host+"/api", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				w := httptest.NewRecorder()
				h.proxy.ServeHTTP(w, req)
			}

			b.StopTimer()
			reportTraces(b, h.col.traces)
		})
	}
}

// =============================================================================
// Benchmark: Sustained concurrent load (throughput + latency distribution)
// Simulates realistic sustained traffic and reports percentiles.
// =============================================================================

func TestBenchmarkSustainedLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sustained load test in short mode")
	}

	h := newBenchHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[1,2,3]}`))
	}))

	token := h.mint(t, []jwe.Credential{
		{Header: "DD-API-KEY", Value: "datadog-api-key-12345"},
		{Header: "DD-APPLICATION-KEY", Value: "datadog-app-key-67890"},
	})

	concurrency := []int{1, 10, 50, 100, 200}
	duration := 3 * time.Second

	for _, c := range concurrency {
		t.Run(fmt.Sprintf("%d_goroutines", c), func(t *testing.T) {
			h.col.reset()
			var totalRequests atomic.Int64
			var errors atomic.Int64

			ctx, cancel := timeoutContext(duration)
			defer cancel()

			var wg sync.WaitGroup
			for range c {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}

						req := httptest.NewRequest("GET", "/https/"+h.host+"/api/v2/metrics", nil)
						req.Header.Set("Authorization", "Bearer "+token)
						w := httptest.NewRecorder()
						h.proxy.ServeHTTP(w, req)

						totalRequests.Add(1)
						if w.Code != http.StatusOK {
							errors.Add(1)
						}
					}
				}()
			}

			wg.Wait()

			total := totalRequests.Load()
			errs := errors.Load()
			rps := float64(total) / duration.Seconds()

			t.Logf("=== %d goroutines, %.1fs ===", c, duration.Seconds())
			t.Logf("  total requests:  %d", total)
			t.Logf("  errors:          %d", errs)
			t.Logf("  throughput:      %.0f req/s", rps)
			reportTracesTest(t, h.col.traces)
		})
	}
}

func timeoutContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// =============================================================================
// Trace reporting helpers
// =============================================================================

func reportTraces(b *testing.B, traces []RequestTrace) {
	if len(traces) == 0 {
		return
	}

	var (
		totalDenyList  time.Duration
		totalDecrypt   time.Duration
		totalBuild     time.Duration
		totalUpstream  time.Duration
		totalStream    time.Duration
		totalOverall   time.Duration
	)

	for _, t := range traces {
		totalDenyList += t.DenyListCheck
		totalDecrypt += t.JWEDecrypt
		totalBuild += t.RequestBuild
		totalUpstream += t.UpstreamRoundTrip
		totalStream += t.ResponseStream
		totalOverall += t.Total
	}

	n := len(traces)
	b.ReportMetric(float64(totalDenyList.Nanoseconds())/float64(n), "ns/deny-list")
	b.ReportMetric(float64(totalDecrypt.Nanoseconds())/float64(n), "ns/jwe-decrypt")
	b.ReportMetric(float64(totalBuild.Nanoseconds())/float64(n), "ns/req-build")
	b.ReportMetric(float64(totalUpstream.Nanoseconds())/float64(n), "ns/upstream")
	b.ReportMetric(float64(totalStream.Nanoseconds())/float64(n), "ns/response")
	b.ReportMetric(float64(totalOverall.Nanoseconds())/float64(n), "ns/total")
}

func reportTracesTest(t *testing.T, traces []RequestTrace) {
	if len(traces) == 0 {
		return
	}

	totals := extractDurations(traces, func(tr RequestTrace) time.Duration { return tr.Total })
	decrypts := extractDurations(traces, func(tr RequestTrace) time.Duration { return tr.JWEDecrypt })
	upstreams := extractDurations(traces, func(tr RequestTrace) time.Duration { return tr.UpstreamRoundTrip })
	denyLists := extractDurations(traces, func(tr RequestTrace) time.Duration { return tr.DenyListCheck })

	t.Logf("  --- total latency ---")
	reportPercentiles(t, "    total", totals)
	t.Logf("  --- phase breakdown (avg) ---")
	t.Logf("    deny_list:   %s", avg(denyLists))
	t.Logf("    jwe_decrypt: %s", avg(decrypts))
	t.Logf("    upstream:    %s", avg(upstreams))
	t.Logf("  --- phase breakdown (p99) ---")
	t.Logf("    deny_list:   %s", percentile(denyLists, 0.99))
	t.Logf("    jwe_decrypt: %s", percentile(decrypts, 0.99))
	t.Logf("    upstream:    %s", percentile(upstreams, 0.99))

	proxyOverhead := make([]time.Duration, len(traces))
	for i, tr := range traces {
		proxyOverhead[i] = tr.Total - tr.UpstreamRoundTrip - tr.ResponseStream
	}
	sort.Slice(proxyOverhead, func(i, j int) bool { return proxyOverhead[i] < proxyOverhead[j] })
	t.Logf("  --- proxy overhead (total - upstream - response_stream) ---")
	reportPercentiles(t, "    overhead", proxyOverhead)
}

func extractDurations(traces []RequestTrace, fn func(RequestTrace) time.Duration) []time.Duration {
	ds := make([]time.Duration, len(traces))
	for i, t := range traces {
		ds[i] = fn(t)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds
}

func avg(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range ds {
		total += d
	}
	return total / time.Duration(len(ds))
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func reportPercentiles(t *testing.T, prefix string, sorted []time.Duration) {
	t.Logf("%s  p50=%s  p90=%s  p99=%s  max=%s",
		prefix,
		percentile(sorted, 0.50),
		percentile(sorted, 0.90),
		percentile(sorted, 0.99),
		sorted[len(sorted)-1],
	)
}
