package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FakeBackendAPI simulates an external API (like Datadog) for proxy testing
type FakeBackendAPI struct {
	server *http.Server
	port   string

	// Track requests for verification
	mu       sync.Mutex
	requests []BackendRequest
}

// BackendRequest captures details of a request to the fake backend
type BackendRequest struct {
	Method        string
	Path          string
	Authorization string
	Body          string
}

// NewFakeBackendAPI creates a new fake backend API server
func NewFakeBackendAPI(port string) *FakeBackendAPI {
	api := &FakeBackendAPI{
		port:     port,
		requests: make([]BackendRequest, 0),
	}

	mux := http.NewServeMux()

	// Metrics endpoint
	mux.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Capture request
		body, _ := io.ReadAll(r.Body)
		api.mu.Lock()
		api.requests = append(api.requests, BackendRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
			Authorization: r.Header.Get("Authorization"),
			Body:          string(body),
		})
		api.mu.Unlock()

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"data": map[string]any{
				"result_type": "matrix",
				"result":      []any{},
			},
		})
	})

	// Logs endpoint
	mux.HandleFunc("/api/v2/logs", func(w http.ResponseWriter, r *http.Request) {
		// Capture request
		body, _ := io.ReadAll(r.Body)
		api.mu.Lock()
		api.requests = append(api.requests, BackendRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
			Authorization: r.Header.Get("Authorization"),
			Body:          string(body),
		})
		api.mu.Unlock()

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"data":   []any{},
		})
	})

	// Forbidden endpoint (not in allowlist)
	mux.HandleFunc("/api/v3/forbidden", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		api.requests = append(api.requests, BackendRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
			Authorization: r.Header.Get("Authorization"),
		})
		api.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "This endpoint should be blocked by path allowlist",
		})
	})

	api.server = &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	return api
}

// Start starts the fake backend API server
func (api *FakeBackendAPI) Start() error {
	go func() {
		if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

// Stop stops the fake backend API server
func (api *FakeBackendAPI) Stop() error {
	return api.server.Close()
}

// GetRequests returns all captured requests
func (api *FakeBackendAPI) GetRequests() []BackendRequest {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]BackendRequest{}, api.requests...)
}

// ClearRequests clears all captured requests
func (api *FakeBackendAPI) ClearRequests() {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.requests = make([]BackendRequest, 0)
}

// TestExecutionProxyBasicFlow tests the complete execution proxy flow
func TestExecutionProxyBasicFlow(t *testing.T) {
	// Start fake backend API
	backend := NewFakeBackendAPI("9091")
	err := backend.Start()
	require.NoError(t, err, "Failed to start fake backend")
	defer backend.Stop()

	// Start fake service OAuth server
	serviceOAuth := NewFakeServiceOAuthServer("9092")
	err = serviceOAuth.Start()
	require.NoError(t, err, "Failed to start fake service OAuth")
	defer serviceOAuth.Stop()

	// Start mcp-front with proxy-enabled service
	startMCPFront(t, "config/config.execution-proxy-test.json",
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id",
		"GOOGLE_CLIENT_SECRET=test-client-secret",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
		"DATADOG_CLIENT_ID=datadog-client-id",
		"DATADOG_CLIENT_SECRET=datadog-client-secret",
	)

	waitForMCPFront(t)

	// Step 1: Authenticate user via OAuth
	t.Log("Step 1: Authenticating user via OAuth...")
	oauthToken := performOAuthFlow(t)
	require.NotEmpty(t, oauthToken, "OAuth token should not be empty")

	// Step 2: Connect user to the datadog service
	t.Log("Step 2: Connecting user to datadog service...")
	connectUserToService(t, "datadog", oauthToken)

	// Step 3: Request execution token
	t.Log("Step 3: Requesting execution token...")
	executionTokenResp := requestExecutionToken(t, oauthToken, "datadog", "exec-test-123")
	require.NotEmpty(t, executionTokenResp.Token, "Execution token should not be empty")
	require.NotEmpty(t, executionTokenResp.ProxyURL, "Proxy URL should not be empty")
	assert.Contains(t, executionTokenResp.ProxyURL, "/proxy/datadog")

	t.Logf("Got execution token: %s", executionTokenResp.Token[:20]+"...")
	t.Logf("Proxy URL: %s", executionTokenResp.ProxyURL)

	// Step 4: Use execution token to proxy request to backend
	t.Log("Step 4: Making proxied request...")
	backend.ClearRequests()

	resp, err := makeProxiedRequest(t, executionTokenResp.Token, "/api/v1/metrics", "GET", nil)
	require.NoError(t, err, "Proxied request should succeed")
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode, "Proxy request should succeed")

	// Step 5: Verify backend received request with real user credentials
	t.Log("Step 5: Verifying backend received request with real credentials...")
	requests := backend.GetRequests()
	require.Len(t, requests, 1, "Backend should have received exactly one request")

	backendReq := requests[0]
	assert.Equal(t, "GET", backendReq.Method)
	assert.Equal(t, "/api/v1/metrics", backendReq.Path)
	assert.Equal(t, "Bearer service-oauth-access-token", backendReq.Authorization,
		"Backend should receive real user OAuth token, not execution token")

	t.Log("✅ Execution proxy flow completed successfully")
}

// TestExecutionProxyPathRestrictions tests that path allowlisting works
func TestExecutionProxyPathRestrictions(t *testing.T) {
	// Start fake backend API
	backend := NewFakeBackendAPI("9091")
	err := backend.Start()
	require.NoError(t, err, "Failed to start fake backend")
	defer backend.Stop()

	// Start fake service OAuth server
	serviceOAuth := NewFakeServiceOAuthServer("9092")
	err = serviceOAuth.Start()
	require.NoError(t, err, "Failed to start fake service OAuth")
	defer serviceOAuth.Stop()

	// Start mcp-front
	startMCPFront(t, "config/config.execution-proxy-test.json",
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id",
		"GOOGLE_CLIENT_SECRET=test-client-secret",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
		"DATADOG_CLIENT_ID=datadog-client-id",
		"DATADOG_CLIENT_SECRET=datadog-client-secret",
	)

	waitForMCPFront(t)

	// Authenticate and connect
	oauthToken := performOAuthFlow(t)
	connectUserToService(t, "datadog", oauthToken)

	// Create execution session with specific allowed paths
	t.Log("Creating execution session with path restrictions...")
	reqBody, _ := json.Marshal(map[string]any{
		"execution_id":         "exec-path-test",
		"target_service":       "datadog",
		"max_ttl_seconds":      300,
		"idle_timeout_seconds": 30,
		"allowed_paths":        []string{"/api/v1/metrics"},
	})

	req, _ := http.NewRequest("POST", "http://localhost:8080/api/execution-session", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+oauthToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var tokenResp ExecutionTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)

	// Test allowed path - should succeed
	t.Log("Testing allowed path /api/v1/metrics...")
	resp, err = makeProxiedRequest(t, tokenResp.Token, "/api/v1/metrics", "GET", nil)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode, "Allowed path should succeed")

	// Test forbidden path - should fail
	t.Log("Testing forbidden path /api/v2/logs...")
	resp, err = makeProxiedRequest(t, tokenResp.Token, "/api/v2/logs", "GET", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 403, resp.StatusCode, "Forbidden path should be rejected with 403 Forbidden")

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Forbidden path response: %s", string(body))
	assert.Contains(t, string(body), "not allowed", "Error message should mention path not allowed")

	t.Log("✅ Path restrictions working correctly")
}

// TestExecutionProxyTokenExpiration tests that expired tokens are rejected
func TestExecutionProxyTokenExpiration(t *testing.T) {
	// Start fake backend
	backend := NewFakeBackendAPI("9091")
	err := backend.Start()
	require.NoError(t, err)
	defer backend.Stop()

	// Start fake service OAuth
	serviceOAuth := NewFakeServiceOAuthServer("9092")
	err = serviceOAuth.Start()
	require.NoError(t, err)
	defer serviceOAuth.Stop()

	// Start mcp-front
	startMCPFront(t, "config/config.execution-proxy-test.json",
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id",
		"GOOGLE_CLIENT_SECRET=test-client-secret",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
		"DATADOG_CLIENT_ID=datadog-client-id",
		"DATADOG_CLIENT_SECRET=datadog-client-secret",
	)

	waitForMCPFront(t)

	// Authenticate and connect
	oauthToken := performOAuthFlow(t)
	connectUserToService(t, "datadog", oauthToken)

	// Create execution session with very short idle timeout (2 seconds)
	t.Log("Creating execution session with 2-second idle timeout...")
	reqBody, _ := json.Marshal(map[string]any{
		"execution_id":         "exec-expiry-test",
		"target_service":       "datadog",
		"max_ttl_seconds":      300,
		"idle_timeout_seconds": 2,
	})

	req, _ := http.NewRequest("POST", "http://localhost:8080/api/execution-session", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+oauthToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var tokenResp ExecutionTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)

	// Use token immediately - should succeed
	t.Log("Using token immediately...")
	resp, err = makeProxiedRequest(t, tokenResp.Token, "/api/v1/metrics", "GET", nil)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode, "Fresh token should work")

	// Wait for token to expire
	t.Log("Waiting for token to expire...")
	time.Sleep(3 * time.Second)

	// Try using expired token - should fail
	t.Log("Using expired token...")
	resp, err = makeProxiedRequest(t, tokenResp.Token, "/api/v1/metrics", "GET", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, 401, resp.StatusCode, "Expired token should be rejected")

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "expired", "Error should mention token expiration")

	t.Log("✅ Token expiration working correctly")
}

// TestExecutionProxyServiceIsolation tests that tokens are scoped to specific services
func TestExecutionProxyServiceIsolation(t *testing.T) {
	// Start fake backend
	backend := NewFakeBackendAPI("9091")
	err := backend.Start()
	require.NoError(t, err)
	defer backend.Stop()

	// Start fake service OAuth
	serviceOAuth := NewFakeServiceOAuthServer("9092")
	err = serviceOAuth.Start()
	require.NoError(t, err)
	defer serviceOAuth.Stop()

	// Start mcp-front
	startMCPFront(t, "config/config.execution-proxy-test.json",
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id",
		"GOOGLE_CLIENT_SECRET=test-client-secret",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
		"DATADOG_CLIENT_ID=datadog-client-id",
		"DATADOG_CLIENT_SECRET=datadog-client-secret",
	)

	waitForMCPFront(t)

	// Authenticate and connect
	oauthToken := performOAuthFlow(t)
	connectUserToService(t, "datadog", oauthToken)

	// Request execution token for datadog service
	tokenResp := requestExecutionToken(t, oauthToken, "datadog", "exec-isolation-test")

	// Try using datadog token for a different service (should fail)
	t.Log("Attempting to use datadog token for linear service...")
	req, _ := http.NewRequest("GET", "http://localhost:8080/proxy/linear/api/v1/issues", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.Token)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, 401, resp.StatusCode, "Token for datadog should not work for linear")

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "not valid for service", "Error should mention service mismatch")

	t.Log("✅ Service isolation working correctly")
}

// Helper functions

// ExecutionTokenResponse represents the response from session creation
type ExecutionTokenResponse struct {
	SessionID       string    `json:"session_id"`
	Token           string    `json:"token"`
	ProxyURL        string    `json:"proxy_url"`
	IdleTimeout     int       `json:"idle_timeout"`
	MaxTTL          int       `json:"max_ttl"`
	ExpiresAt       time.Time `json:"expires_at"`
	MaxTTLExpiresAt time.Time `json:"max_ttl_expires_at"`
}

// performOAuthFlow simulates the OAuth flow and returns an OAuth token
func performOAuthFlow(t *testing.T) string {
	t.Helper()

	// Register a client
	registerResp, err := http.Post("http://localhost:8080/register", "application/json",
		bytes.NewReader([]byte(`{"redirect_uris":["http://localhost:8080/callback"]}`)))
	require.NoError(t, err)
	defer registerResp.Body.Close()

	var regResult map[string]any
	err = json.NewDecoder(registerResp.Body).Decode(&regResult)
	require.NoError(t, err)

	clientID := regResult["client_id"].(string)

	// Start authorization
	authURL := fmt.Sprintf("http://localhost:8080/authorize?client_id=%s&redirect_uri=http://localhost:8080/callback&response_type=code&state=test-state&code_challenge=test-challenge&code_challenge_method=plain",
		clientID)

	resp, err := http.Get(authURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should redirect to Google OAuth (fake server), which redirects back with code
	// Parse callback URL from response
	body, _ := io.ReadAll(resp.Body)
	_ = body

	// For testing, we'll simulate getting the code
	// In real flow, this would come from the callback
	code := "test-auth-code"

	// Exchange code for token
	tokenReq := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=http://localhost:8080/callback&client_id=%s&code_verifier=test-challenge",
		code, clientID)

	tokenResp, err := http.Post("http://localhost:8080/token", "application/x-www-form-urlencoded",
		bytes.NewReader([]byte(tokenReq)))
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)

	accessToken, ok := tokenResult["access_token"].(string)
	require.True(t, ok, "Should have access token")

	return accessToken
}

// connectUserToService simulates connecting a user to a service via OAuth
func connectUserToService(t *testing.T, serviceName, oauthToken string) {
	t.Helper()

	// Start OAuth connection flow
	connectURL := fmt.Sprintf("http://localhost:8080/oauth/connect?service=%s", serviceName)
	req, _ := http.NewRequest("GET", connectURL, nil)
	req.Header.Set("Authorization", "Bearer "+oauthToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should redirect to service OAuth, which redirects back with code
	// Simulate the callback
	callbackURL := fmt.Sprintf("http://localhost:8080/oauth/callback/%s?code=service-auth-code&state=test-state", serviceName)
	callbackResp, err := http.Get(callbackURL)
	require.NoError(t, err)
	callbackResp.Body.Close()
}

// requestExecutionToken creates an execution session and returns the response
func requestExecutionToken(t *testing.T, oauthToken, serviceName, executionID string) ExecutionTokenResponse {
	t.Helper()

	reqBody, _ := json.Marshal(map[string]any{
		"execution_id":         executionID,
		"target_service":       serviceName,
		"max_ttl_seconds":      300,
		"idle_timeout_seconds": 30,
	})

	req, _ := http.NewRequest("POST", "http://localhost:8080/api/execution-session", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+oauthToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "Failed to create execution session")
	defer resp.Body.Close()

	require.Equal(t, 200, resp.StatusCode, "Session creation should succeed")

	var tokenResp ExecutionTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err, "Failed to decode session response")

	return tokenResp
}

// makeProxiedRequest makes a request through the proxy
func makeProxiedRequest(t *testing.T, executionToken, path, method string, body []byte) (*http.Response, error) {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, "http://localhost:8080/proxy/datadog"+path, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+executionToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return http.DefaultClient.Do(req)
}

// TestExecutionProxyConcurrentRequests tests concurrent requests to the same session
func TestExecutionProxyConcurrentRequests(t *testing.T) {
	// Start fake backend API
	backend := NewFakeBackendAPI("9091")
	err := backend.Start()
	require.NoError(t, err, "Failed to start fake backend")
	defer backend.Stop()

	// Start fake service OAuth server
	serviceOAuth := NewFakeServiceOAuthServer("9092")
	err = serviceOAuth.Start()
	require.NoError(t, err, "Failed to start fake service OAuth")
	defer serviceOAuth.Stop()

	// Start mcp-front
	startMCPFront(t, "config/config.execution-proxy-test.json",
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id",
		"GOOGLE_CLIENT_SECRET=test-client-secret",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
		"DATADOG_CLIENT_ID=datadog-client-id",
		"DATADOG_CLIENT_SECRET=datadog-client-secret",
	)

	waitForMCPFront(t)

	// Authenticate and connect
	oauthToken := performOAuthFlow(t)
	connectUserToService(t, "datadog", oauthToken)

	// Create session
	t.Log("Creating execution session...")
	tokenResp := requestExecutionToken(t, oauthToken, "datadog", "exec-concurrent-test")

	// Clear backend requests
	backend.ClearRequests()

	// Launch 100 concurrent requests
	const numRequests = 100
	t.Logf("Launching %d concurrent proxy requests...", numRequests)

	var wg sync.WaitGroup
	errChan := make(chan error, numRequests)
	successCount := make(chan int, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(requestNum int) {
			defer wg.Done()

			resp, err := makeProxiedRequest(t, tokenResp.Token, "/api/v1/metrics", "GET", nil)
			if err != nil {
				errChan <- fmt.Errorf("request %d failed: %w", requestNum, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				errChan <- fmt.Errorf("request %d got status %d", requestNum, resp.StatusCode)
				return
			}

			successCount <- 1
		}(i)
	}

	// Wait for all requests to complete
	wg.Wait()
	close(errChan)
	close(successCount)

	// Check for errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}
	require.Empty(t, errors, "Some concurrent requests failed")

	// Count successes
	count := 0
	for range successCount {
		count++
	}
	assert.Equal(t, numRequests, count, "All requests should succeed")

	// Verify backend received all requests
	backendRequests := backend.GetRequests()
	assert.Equal(t, numRequests, len(backendRequests), "Backend should receive all requests")

	// Verify session request count is accurate
	t.Log("Verifying session request count...")

	// Get session info
	req, _ := http.NewRequest("GET", "http://localhost:8080/api/execution-sessions", nil)
	req.Header.Set("Authorization", "Bearer "+oauthToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var sessions []map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&sessions)
	require.NoError(t, err)
	require.Len(t, sessions, 1, "Should have exactly one session")

	requestCount := int(sessions[0]["request_count"].(float64))
	assert.Equal(t, numRequests, requestCount, "Session request_count should be exactly %d (no race condition)", numRequests)

	t.Logf("✅ All %d concurrent requests succeeded, request_count = %d (accurate!)", numRequests, requestCount)
}
