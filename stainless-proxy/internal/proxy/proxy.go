package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stainless-api/stainless-proxy/internal/hostmatch"
	"github.com/stainless-api/stainless-proxy/internal/jwe"
	"github.com/stainless-api/stainless-proxy/internal/revocation"
	"github.com/stainless-api/stainless-proxy/internal/secretutil"
)

type Proxy struct {
	client    *http.Client
	decryptor jwe.Decryptor
	denyList  *revocation.DenyList
	OnTrace   TraceCallback
}

func New(decryptor jwe.Decryptor, denyList *revocation.DenyList) *Proxy {
	return &Proxy{
		client:    &http.Client{},
		decryptor: decryptor,
		denyList:  denyList,
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	trace := &RequestTrace{
		Start:  time.Now(),
		Method: r.Method,
	}
	defer p.finishTrace(trace)

	token, ok := extractBearer(r)
	if !ok {
		trace.StatusCode = http.StatusUnauthorized
		writeError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
		return
	}

	t0 := time.Now()
	hash := hashJWE(token)
	if p.denyList.IsRevoked(hash) {
		trace.DenyListCheck = time.Since(t0)
		trace.StatusCode = http.StatusForbidden
		writeError(w, http.StatusForbidden, "token revoked")
		return
	}
	trace.DenyListCheck = time.Since(t0)

	t0 = time.Now()
	payload, err := p.decryptor.Decrypt(token)
	trace.JWEDecrypt = time.Since(t0)
	if err != nil {
		slog.Warn("JWE decryption failed", "error", err)
		trace.StatusCode = http.StatusUnauthorized
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	trace.CredentialCount = len(payload.Credentials)

	t0 = time.Now()
	targetScheme, targetHost, targetPath, err := parseTargetFromPath(r.URL.Path)
	trace.PathParse = time.Since(t0)
	if err != nil {
		trace.StatusCode = http.StatusBadRequest
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	trace.TargetHost = targetHost
	trace.TargetPath = targetPath

	t0 = time.Now()
	if !hostmatch.Match(targetHost, payload.AllowedHosts) {
		trace.HostMatch = time.Since(t0)
		slog.Warn("host not allowed", "host", targetHost, "allowed", payload.AllowedHosts)
		trace.StatusCode = http.StatusForbidden
		writeError(w, http.StatusForbidden, "target host not allowed")
		return
	}
	trace.HostMatch = time.Since(t0)

	t0 = time.Now()
	targetURL := &url.URL{
		Scheme:   targetScheme,
		Host:     targetHost,
		Path:     targetPath,
		RawQuery: r.URL.RawQuery,
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		trace.RequestBuild = time.Since(t0)
		trace.StatusCode = http.StatusInternalServerError
		writeError(w, http.StatusInternalServerError, "failed to create request")
		return
	}

	copyHeaders(outReq.Header, r.Header)
	trace.RequestBuild = time.Since(t0)

	slog.Info("proxying request",
		"method", r.Method,
		"target", targetURL.Redacted(),
		"credentials_count", len(payload.Credentials),
	)

	// secret.Do wraps credential injection + upstream call. This ensures:
	//   - Credential string values (from payload) are used then zeroed
	//   - net/http transport's internal write buffers (containing serialized
	//     credential headers) are marked for zeroing on GC collection
	//   - Stack frames and registers are zeroed on return
	var resp *http.Response
	secretutil.Do(func() {
		for _, cred := range payload.Credentials {
			outReq.Header.Set(cred.Header, cred.Value)
		}

		t0 = time.Now()
		resp, err = p.client.Do(outReq)
		trace.UpstreamRoundTrip = time.Since(t0)
	})
	if err != nil {
		slog.Error("upstream request failed", "error", err)
		trace.StatusCode = http.StatusBadGateway
		writeError(w, http.StatusBadGateway, "upstream request failed")
		return
	}
	defer resp.Body.Close()
	trace.StatusCode = resp.StatusCode

	t0 = time.Now()
	for k, v := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	var responseBytes int64
	if isStreaming(resp) {
		flusher, ok := w.(http.Flusher)
		buf := make([]byte, 4096)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				responseBytes += int64(n)
				if ok {
					flusher.Flush()
				}
			}
			if readErr != nil {
				break
			}
		}
	} else {
		responseBytes, _ = io.Copy(w, resp.Body)
	}
	trace.ResponseStream = time.Since(t0)
	trace.ResponseBodyBytes = responseBytes
}

func (p *Proxy) finishTrace(trace *RequestTrace) {
	trace.Total = time.Since(trace.Start)

	slog.Info("request completed",
		"method", trace.Method,
		"target_host", trace.TargetHost,
		"status", trace.StatusCode,
		"total", trace.Total,
		"deny_list_check", trace.DenyListCheck,
		"jwe_decrypt", trace.JWEDecrypt,
		"path_parse", trace.PathParse,
		"host_match", trace.HostMatch,
		"request_build", trace.RequestBuild,
		"upstream_round_trip", trace.UpstreamRoundTrip,
		"response_stream", trace.ResponseStream,
		"credentials", trace.CredentialCount,
		"response_bytes", trace.ResponseBodyBytes,
	)

	if p.OnTrace != nil {
		p.OnTrace(*trace)
	}
}

// parseTargetFromPath extracts scheme, host, and path from /{scheme}/{host}/{path...}
func parseTargetFromPath(reqPath string) (scheme, host, path string, err error) {
	// Strip leading slash
	trimmed := strings.TrimPrefix(reqPath, "/")
	if trimmed == "" {
		return "", "", "", fmt.Errorf("empty path")
	}

	// First segment is scheme
	slashIdx := strings.IndexByte(trimmed, '/')
	if slashIdx == -1 {
		return "", "", "", fmt.Errorf("missing host in path")
	}
	scheme = trimmed[:slashIdx]
	if scheme != "http" && scheme != "https" {
		return "", "", "", fmt.Errorf("invalid scheme: %s", scheme)
	}

	rest := trimmed[slashIdx+1:]

	// Second segment is host (may include port)
	slashIdx = strings.IndexByte(rest, '/')
	if slashIdx == -1 {
		host = rest
		path = "/"
	} else {
		host = rest[:slashIdx]
		path = rest[slashIdx:]
	}

	if host == "" {
		return "", "", "", fmt.Errorf("empty host")
	}

	return scheme, host, path, nil
}

func extractBearer(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	token := auth[7:]
	if token == "" {
		return "", false
	}
	return token, true
}

func hashJWE(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func copyHeaders(dst, src http.Header) {
	for k, v := range src {
		if k == "Connection" || k == "Upgrade" || k == "Host" ||
			k == "Authorization" || k == "Cookie" {
			continue
		}
		dst[k] = v
	}
}

func isHopByHop(header string) bool {
	switch header {
	case "Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers",
		"Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}

func isStreaming(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "text/event-stream")
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":"%s"}`, message)
}
