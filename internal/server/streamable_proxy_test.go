package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendStreamablePost(t *testing.T) {
	t.Run("sends POST with correct headers", func(t *testing.T) {
		var capturedReq *http.Request
		var capturedBody []byte

		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedReq = r
			capturedBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		body := []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`)
		headers := http.Header{}
		headers.Set("User-Agent", "test-client")
		headers.Set("Mcp-Session-Id", "session-123")

		cfg := &config.MCPClientConfig{
			URL: backend.URL,
			Headers: map[string]string{
				"Authorization": "Bearer tok",
			},
			Timeout: 5 * time.Second,
		}

		resp, err := sendStreamablePost(context.Background(), body, headers, cfg)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.MethodPost, capturedReq.Method)
		assert.Equal(t, body, capturedBody)
		assert.Equal(t, "application/json, text/event-stream", capturedReq.Header.Get("Accept"))
		assert.Equal(t, "Bearer tok", capturedReq.Header.Get("Authorization"))
		assert.Equal(t, "test-client", capturedReq.Header.Get("User-Agent"))
		assert.Equal(t, "session-123", capturedReq.Header.Get("Mcp-Session-Id"))
	})

	t.Run("config headers override source headers", func(t *testing.T) {
		var capturedAuth string

		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("X-Api-Key")
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		headers := http.Header{}
		headers.Set("X-Api-Key", "from-client")

		cfg := &config.MCPClientConfig{
			URL: backend.URL,
			Headers: map[string]string{
				"X-Api-Key": "from-config",
			},
			Timeout: 5 * time.Second,
		}

		resp, err := sendStreamablePost(context.Background(), nil, headers, cfg)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, "from-config", capturedAuth)
	})

	t.Run("connection failure returns error", func(t *testing.T) {
		cfg := &config.MCPClientConfig{
			URL:     "http://localhost:1",
			Timeout: 100 * time.Millisecond,
		}

		_, err := sendStreamablePost(context.Background(), nil, http.Header{}, cfg)
		assert.Error(t, err)
	})
}

func TestInitBackendSession(t *testing.T) {
	t.Run("successful initialization", func(t *testing.T) {
		var requests []struct {
			Body    json.RawMessage
			Headers http.Header
		}

		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			requests = append(requests, struct {
				Body    json.RawMessage
				Headers http.Header
			}{Body: body, Headers: r.Header.Clone()})

			if len(requests) == 1 {
				w.Header().Set("Mcp-Session-Id", "new-session-abc")
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		srcHeaders := http.Header{}
		srcHeaders.Set("Mcp-Session-Id", "old-stale-session")
		srcHeaders.Set("User-Agent", "test")

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		sessionID, err := initBackendSession(context.Background(), srcHeaders, cfg)
		require.NoError(t, err)
		assert.Equal(t, "new-session-abc", sessionID)

		require.Len(t, requests, 2)

		// First request: initialize (must not carry old session ID)
		var initMsg map[string]any
		require.NoError(t, json.Unmarshal(requests[0].Body, &initMsg))
		assert.Equal(t, "initialize", initMsg["method"])
		assert.Empty(t, requests[0].Headers.Get("Mcp-Session-Id"))

		// Second request: initialized notification (must carry new session ID)
		var notifyMsg map[string]any
		require.NoError(t, json.Unmarshal(requests[1].Body, &notifyMsg))
		assert.Equal(t, "notifications/initialized", notifyMsg["method"])
		assert.Equal(t, "new-session-abc", requests[1].Headers.Get("Mcp-Session-Id"))
	})

	t.Run("backend returns no session ID", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		_, err := initBackendSession(context.Background(), http.Header{}, cfg)
		assert.ErrorIs(t, err, errNoBackendSessionID)
	})

	t.Run("backend initialize returns non-200", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		_, err := initBackendSession(context.Background(), http.Header{}, cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status 503")
	})

	t.Run("notification failure is non-fatal", func(t *testing.T) {
		callCount := 0
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				w.Header().Set("Mcp-Session-Id", "sess-ok")
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		sessionID, err := initBackendSession(context.Background(), http.Header{}, cfg)
		require.NoError(t, err)
		assert.Equal(t, "sess-ok", sessionID)
	})

	t.Run("initialize request failure", func(t *testing.T) {
		cfg := &config.MCPClientConfig{
			URL:     "http://localhost:1",
			Timeout: 100 * time.Millisecond,
		}

		_, err := initBackendSession(context.Background(), http.Header{}, cfg)
		assert.Error(t, err)
	})
}

func TestForwardStreamablePostToBackend(t *testing.T) {
	t.Run("successful JSON response", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodPost, "/test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, cfg)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"result"`)
	})

	t.Run("successful SSE response", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Mcp-Session-Id", "sess-42")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"))
			w.(http.Flusher).Flush()
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodPost, "/test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, cfg)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		assert.Equal(t, "sess-42", rec.Header().Get("Mcp-Session-Id"))
		assert.Contains(t, rec.Body.String(), `"result"`)
	})

	t.Run("session recovery on 404", func(t *testing.T) {
		callCount := 0
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			body, _ := io.ReadAll(r.Body)

			switch callCount {
			case 1:
				// Original request — stale session
				assert.Equal(t, "old-session", r.Header.Get("Mcp-Session-Id"))
				w.WriteHeader(http.StatusNotFound)
			case 2:
				// initialize handshake
				var msg map[string]any
				json.Unmarshal(body, &msg)
				assert.Equal(t, "initialize", msg["method"])
				w.Header().Set("Mcp-Session-Id", "fresh-session")
				w.WriteHeader(http.StatusOK)
			case 3:
				// initialized notification
				var msg map[string]any
				json.Unmarshal(body, &msg)
				assert.Equal(t, "notifications/initialized", msg["method"])
				assert.Equal(t, "fresh-session", r.Header.Get("Mcp-Session-Id"))
				w.WriteHeader(http.StatusOK)
			case 4:
				// Retried original request with new session
				assert.Equal(t, "fresh-session", r.Header.Get("Mcp-Session-Id"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"recovered"}`))
			}
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodPost, "/test/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
		req.Header.Set("Mcp-Session-Id", "old-session")
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, cfg)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"recovered"`)
		assert.Equal(t, 4, callCount)
	})

	t.Run("no recovery when 404 without session ID", func(t *testing.T) {
		callCount := 0
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.WriteHeader(http.StatusNotFound)
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodPost, "/test/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, cfg)

		// Should forward the 404 as-is, no recovery attempt
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, 1, callCount)
	})

	t.Run("recovery init failure returns error", func(t *testing.T) {
		callCount := 0
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// init request — return 200 but no session ID
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		req := httptest.NewRequest(http.MethodPost, "/test/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
		req.Header.Set("Mcp-Session-Id", "stale")
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, cfg)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "backend session recovery failed")
	})

	t.Run("backend connection failure", func(t *testing.T) {
		cfg := &config.MCPClientConfig{
			URL:     "http://localhost:1",
			Timeout: 100 * time.Millisecond,
		}

		body := bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
		req := httptest.NewRequest(http.MethodPost, "/test/mcp", body)
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, cfg)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "backend request failed")
	})

	t.Run("request body is preserved for retry", func(t *testing.T) {
		var bodies []string
		callCount := 0

		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			b, _ := io.ReadAll(r.Body)
			bodyStr := string(b)
			bodies = append(bodies, bodyStr)

			switch {
			case callCount == 1:
				w.WriteHeader(http.StatusNotFound)
			case strings.Contains(bodyStr, "initialize"):
				w.Header().Set("Mcp-Session-Id", "new-sess")
				w.WriteHeader(http.StatusOK)
			case strings.Contains(bodyStr, "notifications/initialized"):
				w.WriteHeader(http.StatusOK)
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"ok"}`))
			}
		}))
		defer backend.Close()

		cfg := &config.MCPClientConfig{
			URL:     backend.URL,
			Timeout: 5 * time.Second,
		}

		originalBody := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}`
		req := httptest.NewRequest(http.MethodPost, "/test/mcp", strings.NewReader(originalBody))
		req.Header.Set("Mcp-Session-Id", "old")
		rec := httptest.NewRecorder()

		forwardStreamablePostToBackend(context.Background(), rec, req, cfg)

		assert.Equal(t, http.StatusOK, rec.Code)
		// First and last request should have the original body
		assert.Equal(t, originalBody, bodies[0])
		assert.Equal(t, originalBody, bodies[len(bodies)-1])
	})
}
