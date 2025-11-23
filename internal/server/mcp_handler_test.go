package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/jsonrpc"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockSessionManager struct {
	mock.Mock
}

type mockStorage struct {
	*storage.MemoryStorage
	mock.Mock
}

func (m *mockStorage) GetUserToken(ctx context.Context, userEmail, service string) (*storage.StoredToken, error) {
	if m.Mock.ExpectedCalls != nil {
		args := m.Called(ctx, userEmail, service)
		if args.Get(0) == nil {
			return nil, args.Error(1)
		}
		return args.Get(0).(*storage.StoredToken), args.Error(1)
	}
	return m.MemoryStorage.GetUserToken(ctx, userEmail, service)
}

func (m *mockStorage) UpsertUser(ctx context.Context, email string) error {
	if m.Mock.ExpectedCalls != nil {
		args := m.Called(ctx, email)
		return args.Error(0)
	}
	return m.MemoryStorage.UpsertUser(ctx, email)
}

func (m *mockSessionManager) GetSession(key client.SessionKey) (*client.StdioSession, bool) {
	args := m.Called(key)
	if args.Get(0) == nil {
		return nil, args.Bool(1)
	}
	return args.Get(0).(*client.StdioSession), args.Bool(1)
}

func (m *mockSessionManager) GetOrCreateSession(ctx context.Context, key client.SessionKey, config *config.MCPClientConfig, info mcp.Implementation, setupBaseURL string, userToken string) (*client.StdioSession, error) {
	args := m.Called(ctx, key, config, info, setupBaseURL, userToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.StdioSession), args.Error(1)
}

func (m *mockSessionManager) RemoveSession(key client.SessionKey) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *mockSessionManager) Shutdown() {
	m.Called()
}

// Test helper to create MCPHandler for SSE tests
func createTestMCPHandler(serverName string, serverConfig *config.MCPClientConfig) *MCPHandler {
	mockStore := &mockStorage{
		MemoryStorage: storage.NewMemoryStorage(),
	}
	sessionManager := new(mockSessionManager)
	info := mcp.Implementation{Name: "test", Version: "1.0"}

	return NewMCPHandler(
		serverName,
		serverConfig,
		mockStore,
		"http://localhost:8080",
		info,
		sessionManager,
		nil, // sharedSSEServer
		nil, // sharedMCPServer
		func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			if userEmail == "" {
				return "", fmt.Errorf("no user")
			}
			return "test-token-for-" + serviceName, nil
		},
	)
}

func TestIsMessageRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "message endpoint",
			path:     "/server/message",
			expected: true,
		},
		{
			name:     "message with query",
			path:     "/server/message?sessionId=123",
			expected: true,
		},
		{
			name:     "sse endpoint",
			path:     "/server/sse",
			expected: false,
		},
		{
			name:     "root path",
			path:     "/",
			expected: false,
		},
		{
			name:     "contains message in middle",
			path:     "/server/test/message/other",
			expected: false,
		},
	}

	handler := createTestMCPHandler("test", &config.MCPClientConfig{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, nil)
			result := handler.isMessageRequest(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandleMessageRequest_SSEServer(t *testing.T) {
	// Create a mock backend server
	backendCalled := false
	var capturedRequest *http.Request
	var capturedBody []byte

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		capturedRequest = r
		capturedBody, _ = io.ReadAll(r.Body)

		// Return a JSON-RPC response
		response := jsonrpc.NewResponse(1, map[string]any{"result": "success"})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "test-value")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer backendServer.Close()

	// Create handler for SSE server
	sseConfig := &config.MCPClientConfig{
		URL:           backendServer.URL,
		TransportType: config.MCPClientTypeSSE,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		Timeout: 5 * time.Second,
	}

	handler := createTestMCPHandler("test-sse", sseConfig)

	// Create test request
	requestBody := jsonrpc.Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test/method",
		Params:  json.RawMessage(`{"key": "value"}`),
	}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/test-sse/message?sessionId=optional", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Handle request
	handler.handleMessageRequest(context.Background(), rec, req, "user@example.com", sseConfig)

	// Verify backend was called
	assert.True(t, backendCalled, "Backend should have been called")

	// Verify request forwarding
	assert.Equal(t, "/message?sessionId=optional", capturedRequest.URL.Path+"?"+capturedRequest.URL.RawQuery)
	assert.Equal(t, "Bearer test-token", capturedRequest.Header.Get("Authorization"))
	assert.Equal(t, "application/json", capturedRequest.Header.Get("Content-Type"))
	assert.Equal(t, body, capturedBody)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "test-value", rec.Header().Get("X-Custom-Header"))

	var response jsonrpc.Response
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, float64(1), response.ID)

	result, ok := response.Result.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "success", result["result"])
}

func TestForwardMessageToBackend_URLTransformation(t *testing.T) {
	t.Run("SSE URL with /sse suffix", func(t *testing.T) {
		// Create a mock backend server
		var capturedURL string
		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedURL = r.URL.Path
			response := jsonrpc.NewResponse(1, map[string]any{"result": "success"})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		}))
		defer backendServer.Close()

		// Config URL ends with /sse
		sseConfig := &config.MCPClientConfig{
			URL:           backendServer.URL + "/sse",
			TransportType: config.MCPClientTypeSSE,
		}

		handler := createTestMCPHandler("test-sse", sseConfig)

		requestBody := jsonrpc.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "test/method",
		}
		body, _ := json.Marshal(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/test-sse/message", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.forwardMessageToBackend(context.Background(), rec, req, sseConfig)

		// Verify URL was transformed correctly: /sse -> /message
		assert.Equal(t, "/message", capturedURL, "Should replace /sse with /message, not append")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("SSE URL without /sse suffix", func(t *testing.T) {
		// Create a mock backend server
		var capturedURL string
		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedURL = r.URL.Path
			response := jsonrpc.NewResponse(1, map[string]any{"result": "success"})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(response)
		}))
		defer backendServer.Close()

		// Config URL doesn't end with /sse
		sseConfig := &config.MCPClientConfig{
			URL:           backendServer.URL,
			TransportType: config.MCPClientTypeSSE,
		}

		handler := createTestMCPHandler("test-sse", sseConfig)

		requestBody := jsonrpc.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "test/method",
		}
		body, _ := json.Marshal(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/test-sse/message", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.forwardMessageToBackend(context.Background(), rec, req, sseConfig)

		// Verify URL gets /message appended
		assert.Equal(t, "/message", capturedURL, "Should append /message when URL doesn't end with /sse")
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestForwardMessageToBackend_ErrorCases(t *testing.T) {
	t.Run("backend connection failure", func(t *testing.T) {
		// Use invalid URL to simulate connection failure
		sseConfig := &config.MCPClientConfig{
			URL:           "http://localhost:1", // Port 1 should fail
			TransportType: config.MCPClientTypeSSE,
			Timeout:       100 * time.Millisecond,
		}

		handler := createTestMCPHandler("test-sse", sseConfig)

		requestBody := jsonrpc.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "test/method",
		}
		body, _ := json.Marshal(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/test-sse/message", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		handler.forwardMessageToBackend(context.Background(), rec, req, sseConfig)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response jsonrpc.Response
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotNil(t, response.Error)
		assert.Equal(t, jsonrpc.InternalError, response.Error.Code)
		assert.Equal(t, "backend request failed", response.Error.Message)
	})

	t.Run("backend returns error status", func(t *testing.T) {
		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal Server Error"))
		}))
		defer backendServer.Close()

		sseConfig := &config.MCPClientConfig{
			URL:           backendServer.URL,
			TransportType: config.MCPClientTypeSSE,
		}

		handler := createTestMCPHandler("test-sse", sseConfig)

		req := httptest.NewRequest(http.MethodPost, "/test-sse/message", bytes.NewReader([]byte("{}")))
		rec := httptest.NewRecorder()

		handler.forwardMessageToBackend(context.Background(), rec, req, sseConfig)

		// Should forward the error status
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "Internal Server Error")
	})

	t.Run("invalid request body", func(t *testing.T) {
		handler := createTestMCPHandler("test-sse", &config.MCPClientConfig{})

		// Create a request with a body that fails to read
		req := httptest.NewRequest(http.MethodPost, "/test-sse/message", &failingReader{})
		rec := httptest.NewRecorder()

		handler.forwardMessageToBackend(context.Background(), rec, req, &config.MCPClientConfig{})

		assert.Equal(t, http.StatusOK, rec.Code)

		var response jsonrpc.Response
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotNil(t, response.Error)
		assert.Equal(t, jsonrpc.InternalError, response.Error.Code)
		assert.Equal(t, "failed to read request", response.Error.Message)
	})
}

func TestForwardMessageToBackend_HeaderHandling(t *testing.T) {
	var capturedHeaders http.Header

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header
		w.Header().Set("X-Response-Header", "response-value")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result": "ok"}`))
	}))
	defer backendServer.Close()

	sseConfig := &config.MCPClientConfig{
		URL:           backendServer.URL,
		TransportType: config.MCPClientTypeSSE,
		Headers: map[string]string{
			"Authorization": "Bearer config-token",
			"X-Custom":      "custom-value",
		},
	}

	handler := createTestMCPHandler("test-sse", sseConfig)

	req := httptest.NewRequest(http.MethodPost, "/test-sse/message", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-Request-Header", "request-value")
	rec := httptest.NewRecorder()

	handler.forwardMessageToBackend(context.Background(), rec, req, sseConfig)

	// Verify request headers
	assert.Equal(t, "application/json; charset=utf-8", capturedHeaders.Get("Content-Type"))
	assert.Equal(t, "Bearer config-token", capturedHeaders.Get("Authorization"))
	assert.Equal(t, "custom-value", capturedHeaders.Get("X-Custom"))
	// Original request headers should be forwarded (except sensitive ones)
	assert.Equal(t, "request-value", capturedHeaders.Get("X-Request-Header"))

	// Verify response
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "response-value", rec.Header().Get("X-Response-Header"))
	assert.Equal(t, `{"result": "ok"}`, rec.Body.String())
}

// failingReader simulates a reader that always fails
type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("read error")
}

func TestHandleStreamablePost(t *testing.T) {
	t.Run("JSON response", func(t *testing.T) {
		// Create a mock backend server
		backendCalled := false
		var capturedBody []byte
		var capturedHeaders http.Header

		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendCalled = true
			capturedHeaders = r.Header
			capturedBody, _ = io.ReadAll(r.Body)

			// Return a JSON response
			response := jsonrpc.NewResponse(1, map[string]any{"result": "success"})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Custom-Header", "test-value")
			_ = json.NewEncoder(w).Encode(response)
		}))
		defer backendServer.Close()

		// Create handler for streamable-http server
		streamableConfig := &config.MCPClientConfig{
			URL:           backendServer.URL,
			TransportType: config.MCPClientTypeStreamable,
			Headers: map[string]string{
				"Authorization": "Bearer test-token",
			},
			Timeout: 5 * time.Second,
		}

		handler := createTestMCPHandler("test-streamable", streamableConfig)

		// Create test request
		requestBody := jsonrpc.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "test/method",
			Params:  json.RawMessage(`{"key": "value"}`),
		}
		body, _ := json.Marshal(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/test-streamable", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		// Handle request
		handler.handleStreamablePost(context.Background(), rec, req, "user@example.com", streamableConfig)

		// Verify backend was called
		assert.True(t, backendCalled, "Backend should have been called")

		// Verify request forwarding
		assert.Equal(t, "Bearer test-token", capturedHeaders.Get("Authorization"))
		assert.Equal(t, "application/json", capturedHeaders.Get("Content-Type"))
		assert.Equal(t, "application/json, text/event-stream", capturedHeaders.Get("Accept"))
		assert.Equal(t, body, capturedBody)

		// Verify response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "test-value", rec.Header().Get("X-Custom-Header"))

		var response jsonrpc.Response
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, float64(1), response.ID)
	})

	t.Run("SSE stream response", func(t *testing.T) {
		messages := []string{
			"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":\"Hello\"}}\n\n",
			"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":\"World\"}}\n\n",
		}

		backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return SSE stream
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)

			flusher := w.(http.Flusher)
			for _, msg := range messages {
				_, _ = w.Write([]byte(msg))
				flusher.Flush()
			}
		}))
		defer backendServer.Close()

		streamableConfig := &config.MCPClientConfig{
			URL:           backendServer.URL,
			TransportType: config.MCPClientTypeStreamable,
			Timeout:       5 * time.Second,
		}

		handler := createTestMCPHandler("test-streamable", streamableConfig)

		requestBody := jsonrpc.Request{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
		}
		body, _ := json.Marshal(requestBody)

		req := httptest.NewRequest(http.MethodPost, "/test-streamable", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.handleStreamablePost(context.Background(), rec, req, "user@example.com", streamableConfig)

		// Verify SSE response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))

		// Verify all messages were streamed
		bodyStr := rec.Body.String()
		for _, msg := range messages {
			assert.Contains(t, bodyStr, strings.TrimSpace(msg))
		}
	})

	t.Run("backend error", func(t *testing.T) {
		streamableConfig := &config.MCPClientConfig{
			URL:           "http://localhost:1", // Invalid port
			TransportType: config.MCPClientTypeStreamable,
			Timeout:       100 * time.Millisecond,
		}

		handler := createTestMCPHandler("test-streamable", streamableConfig)

		req := httptest.NewRequest(http.MethodPost, "/test-streamable", bytes.NewReader([]byte("{}")))
		rec := httptest.NewRecorder()

		handler.handleStreamablePost(context.Background(), rec, req, "user@example.com", streamableConfig)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response jsonrpc.Response
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotNil(t, response.Error)
		assert.Equal(t, jsonrpc.InternalError, response.Error.Code)
		assert.Equal(t, "backend request failed", response.Error.Message)
	})
}

func TestHandleStreamableGet(t *testing.T) {
	t.Run("successful SSE stream", func(t *testing.T) {
		// Create a mock SSE backend
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify Accept header
			assert.Equal(t, "text/event-stream", r.Header.Get("Accept"))

			// Send SSE response
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)

			// Send some SSE data
			_, _ = w.Write([]byte("data: {\"type\":\"connected\"}\n\n"))
			w.(http.Flusher).Flush()
		}))
		defer backend.Close()

		// Configure client
		serverConfig := &config.MCPClientConfig{
			URL:           backend.URL,
			TransportType: config.MCPClientTypeStreamable,
			Headers: map[string]string{
				"Authorization": "Bearer test-token",
			},
			Timeout: 5 * time.Second,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		// Create request with Accept header
		req := httptest.NewRequest(http.MethodGet, "/test-streamable", nil)
		req.Header.Set("Accept", "text/event-stream")
		rec := httptest.NewRecorder()

		// Call the function
		handler.handleStreamableGet(context.Background(), rec, req, "user@example.com", serverConfig)

		// Verify response
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "data: {\"type\":\"connected\"}")
	})

	t.Run("missing Accept header", func(t *testing.T) {
		serverConfig := &config.MCPClientConfig{
			URL:           "http://example.com",
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		// Create request without Accept header
		req := httptest.NewRequest(http.MethodGet, "/test-streamable", nil)
		rec := httptest.NewRecorder()

		handler.handleStreamableGet(context.Background(), rec, req, "user@example.com", serverConfig)

		// Should return 406 Not Acceptable
		assert.Equal(t, http.StatusNotAcceptable, rec.Code)
		assert.Contains(t, rec.Body.String(), "GET requests must accept text/event-stream")
	})

	t.Run("wrong Accept header", func(t *testing.T) {
		serverConfig := &config.MCPClientConfig{
			URL:           "http://example.com",
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		// Create request with wrong Accept header
		req := httptest.NewRequest(http.MethodGet, "/test-streamable", nil)
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()

		handler.handleStreamableGet(context.Background(), rec, req, "user@example.com", serverConfig)

		// Should return 406 Not Acceptable
		assert.Equal(t, http.StatusNotAcceptable, rec.Code)
		assert.Contains(t, rec.Body.String(), "GET requests must accept text/event-stream")
	})
}

func TestStreamableTransportRouting(t *testing.T) {
	t.Run("POST request routes to handleStreamablePost", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": "ok"}`))
		}))
		defer backend.Close()

		serverConfig := &config.MCPClientConfig{
			URL:           backend.URL,
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		req := httptest.NewRequest(http.MethodPost, "/test-streamable", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `{"result": "ok"}`)
	})

	t.Run("GET request routes to handleStreamableGet", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: test\n\n"))
		}))
		defer backend.Close()

		serverConfig := &config.MCPClientConfig{
			URL:           backend.URL,
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		req := httptest.NewRequest(http.MethodGet, "/test-streamable", nil)
		req.Header.Set("Accept", "text/event-stream")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	})

	t.Run("unsupported method returns 405", func(t *testing.T) {
		serverConfig := &config.MCPClientConfig{
			URL:           "http://example.com",
			TransportType: config.MCPClientTypeStreamable,
		}

		handler := createTestMCPHandler("test-streamable", serverConfig)

		req := httptest.NewRequest(http.MethodPut, "/test-streamable", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}
