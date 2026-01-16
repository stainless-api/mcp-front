package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestBasicOAuthFlow tests the basic OAuth server functionality
func TestBasicOAuthFlow(t *testing.T) {
	// Start mcp-front with OAuth config
	startMCPFront(t, "config/config.oauth-test.json",
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	)

	// Wait for startup
	waitForMCPFront(t)

	// Test OAuth discovery
	resp, err := http.Get("http://localhost:8080/.well-known/oauth-authorization-server")
	require.NoError(t, err, "Failed to get OAuth discovery")
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode, "OAuth discovery failed")

	var discovery map[string]any
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	require.NoError(t, err, "Failed to decode discovery")

	// Verify required endpoints
	requiredEndpoints := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"registration_endpoint",
	}

	for _, endpoint := range requiredEndpoints {
		_, ok := discovery[endpoint]
		assert.True(t, ok, "Missing required endpoint: %s", endpoint)
	}

	// Verify client_secret_post is advertised
	authMethods, ok := discovery["token_endpoint_auth_methods_supported"].([]any)
	assert.True(t, ok, "token_endpoint_auth_methods_supported should be present")

	var hasNone, hasClientSecretPost bool
	for _, method := range authMethods {
		if method == "none" {
			hasNone = true
		}
		if method == "client_secret_post" {
			hasClientSecretPost = true
		}
	}
	assert.True(t, hasNone, "Should support 'none' auth method for public clients")
	assert.True(t, hasClientSecretPost, "Should support 'client_secret_post' auth method for confidential clients")
}

// TestJWTSecretValidation tests JWT secret length requirements
func TestJWTSecretValidation(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		shouldFail bool
	}{
		{"Short 3-byte secret", "123", true},
		{"Short 16-byte secret", "sixteen-byte-key", true},
		{"Valid 32-byte secret", "demo-jwt-secret-32-bytes-exactly!", false},
		{"Long 64-byte secret", "demo-jwt-secret-32-bytes-exactly!demo-jwt-secret-32-bytes-exactly!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Start mcp-front with specific JWT secret
			mcpCmd := exec.Command("../cmd/mcp-front/mcp-front", "-config", "config/config.oauth-test.json")
			mcpCmd.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"JWT_SECRET=" + tt.secret,
				"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
				"GOOGLE_CLIENT_ID=test-client-id",
				"GOOGLE_CLIENT_SECRET=test-client-secret",
				"MCP_FRONT_ENV=development",
			}

			// Capture stderr
			stderrPipe, _ := mcpCmd.StderrPipe()
			scanner := bufio.NewScanner(stderrPipe)

			if err := mcpCmd.Start(); err != nil {
				t.Fatalf("Failed to start mcp-front: %v", err)
			}

			// Read stderr to check for errors
			errorFound := false
			go func() {
				for scanner.Scan() {
					line := scanner.Text()
					if contains(line, "JWT secret must be at least") {
						errorFound = true
					}
				}
			}()

			// Give it time to start or fail
			time.Sleep(2 * time.Second)

			// Check if it's running
			healthy := checkHealth()

			// Clean up
			if mcpCmd.Process != nil {
				_ = mcpCmd.Process.Kill()
				_ = mcpCmd.Wait()
			}

			if tt.shouldFail {
				assert.False(t, healthy && !errorFound, "Expected failure with short JWT secret but server started successfully")
			} else {
				assert.True(t, healthy, "Expected success with valid JWT secret but server failed to start")
			}
		})
	}
}

// TestClientRegistration tests dynamic client registration (RFC 7591)
func TestClientRegistration(t *testing.T) {
	// Start OAuth server
	mcpCmd := startOAuthServer(t, map[string]string{
		"MCP_FRONT_ENV": "development",
	})
	defer stopServer(mcpCmd)

	if !waitForHealthCheck(30) {
		t.Fatal("OAuth server failed to start")
	}

	t.Run("PublicClientRegistration", func(t *testing.T) {
		// Register a public client (no secret)
		clientReq := map[string]any{
			"redirect_uris": []string{"http://127.0.0.1:6274/oauth/callback/debug"},
			"scope":         "read write",
		}

		body, _ := json.Marshal(clientReq)
		resp, err := http.Post(
			"http://localhost:8080/register",
			"application/json",
			bytes.NewBuffer(body),
		)
		if err != nil {
			t.Fatalf("Failed to register client: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 201 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Client registration failed with status %d: %s", resp.StatusCode, string(body))
		}

		var clientResp map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&clientResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response
		if clientResp["client_id"] == "" {
			t.Error("Client ID should not be empty")
		}
		if clientResp["client_secret"] != nil {
			t.Error("Public client should not have a secret")
		}
		if scope, ok := clientResp["scope"].(string); !ok || scope != "read write" {
			t.Errorf("Expected scope 'read write' as string, got: %v", clientResp["scope"])
		}
	})

	t.Run("MultipleRegistrations", func(t *testing.T) {
		// Register multiple clients and verify they get different IDs
		var clientIDs []string

		for i := range 3 {
			clientReq := map[string]any{
				"redirect_uris": []string{fmt.Sprintf("http://example.com/callback%d", i)},
				"scope":         "read",
			}

			body, _ := json.Marshal(clientReq)
			resp, err := http.Post(
				"http://localhost:8080/register",
				"application/json",
				bytes.NewBuffer(body),
			)
			if err != nil {
				t.Fatalf("Failed to register client %d: %v", i, err)
			}
			defer resp.Body.Close()

			var clientResp map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&clientResp)
			clientIDs = append(clientIDs, clientResp["client_id"].(string))
		}

		// Verify all IDs are unique
		for i := 0; i < len(clientIDs); i++ {
			for j := i + 1; j < len(clientIDs); j++ {
				if clientIDs[i] == clientIDs[j] {
					t.Errorf("Client IDs should be unique, but got duplicate: %s", clientIDs[i])
				}
			}
		}

	})

	t.Run("ConfidentialClientRegistration", func(t *testing.T) {
		// Register a confidential client with client_secret_post
		clientReq := map[string]any{
			"redirect_uris":              []string{"https://example.com/callback"},
			"scope":                      "read write",
			"token_endpoint_auth_method": "client_secret_post",
		}

		body, _ := json.Marshal(clientReq)
		resp, err := http.Post(
			"http://localhost:8080/register",
			"application/json",
			bytes.NewBuffer(body),
		)
		if err != nil {
			t.Fatalf("Failed to register confidential client: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 201 {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Confidential client registration failed with status %d: %s", resp.StatusCode, string(body))
		}

		var clientResp map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&clientResp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response includes client_secret
		if clientResp["client_id"] == "" {
			t.Error("Client ID should not be empty")
		}
		clientSecret, ok := clientResp["client_secret"].(string)
		if !ok || clientSecret == "" {
			t.Error("Confidential client should receive a client_secret")
		}
		// Verify secret has reasonable length (base64 of 32 bytes)
		if len(clientSecret) < 40 {
			t.Errorf("Client secret seems too short: %d chars", len(clientSecret))
		}

		tokenAuthMethod, ok := clientResp["token_endpoint_auth_method"].(string)
		if !ok || tokenAuthMethod != "client_secret_post" {
			t.Errorf("Expected token_endpoint_auth_method 'client_secret_post', got: %v", clientResp["token_endpoint_auth_method"])
		}

		// Verify scope is returned as string
		if scope, ok := clientResp["scope"].(string); !ok || scope != "read write" {
			t.Errorf("Expected scope 'read write' as string, got: %v", clientResp["scope"])
		}
	})

	t.Run("PublicVsConfidentialClients", func(t *testing.T) {
		// Test that public clients don't get secrets and confidential ones do

		// First, create a public client
		publicReq := map[string]any{
			"redirect_uris": []string{"https://public.example.com/callback"},
			"scope":         "read",
			// No token_endpoint_auth_method specified - defaults to "none"
		}

		body, _ := json.Marshal(publicReq)
		resp, err := http.Post(
			"http://localhost:8080/register",
			"application/json",
			bytes.NewBuffer(body),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		var publicResp map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&publicResp)

		// Verify public client has no secret
		if _, hasSecret := publicResp["client_secret"]; hasSecret {
			t.Error("Public client should not have a secret")
		}
		if authMethod := publicResp["token_endpoint_auth_method"]; authMethod != "none" {
			t.Errorf("Public client should have auth method 'none', got: %v", authMethod)
		}

		// Now create a confidential client
		confidentialReq := map[string]any{
			"redirect_uris":              []string{"https://confidential.example.com/callback"},
			"scope":                      "read write",
			"token_endpoint_auth_method": "client_secret_post",
		}

		body, _ = json.Marshal(confidentialReq)
		resp, err = http.Post(
			"http://localhost:8080/register",
			"application/json",
			bytes.NewBuffer(body),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		var confResp map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&confResp)

		// Verify confidential client has a secret
		if secret, ok := confResp["client_secret"].(string); !ok || secret == "" {
			t.Error("Confidential client should have a secret")
		}
		if authMethod := confResp["token_endpoint_auth_method"]; authMethod != "client_secret_post" {
			t.Errorf("Confidential client should have auth method 'client_secret_post', got: %v", authMethod)
		}
	})
}

// TestUserTokenFlow tests the user token management functionality with browser-based SSO
// This test expects the /my/* routes to work with Google SSO (session-based auth),
// not Bearer token auth.
func TestUserTokenFlow(t *testing.T) {
	// Start OAuth server with user token configuration
	mcpCmd := startOAuthServerWithTokenConfig(t)
	defer stopServer(mcpCmd)

	if !waitForHealthCheck(30) {
		t.Fatal("Server failed to start")
	}

	// Create a client with cookie jar to simulate browser behavior
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	t.Run("UnauthenticatedRedirectsToSSO", func(t *testing.T) {
		// Create a client that doesn't follow redirects to test the initial redirect
		noRedirectClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// Try to access /my/tokens without authentication
		resp, err := noRedirectClient.Get("http://localhost:8080/my/tokens")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should get a redirect response
		assert.Equal(t, http.StatusFound, resp.StatusCode, "Should get redirect status")

		// Check the redirect location
		location := resp.Header.Get("Location")
		assert.Contains(t, location, "localhost:9090/auth", "Should redirect to Google OAuth")
		assert.Contains(t, location, "client_id=", "Should include client_id")
		assert.Contains(t, location, "redirect_uri=", "Should include redirect_uri")
		// Extract and validate the state parameter
		parsedURL, err := url.Parse(location)
		require.NoError(t, err)
		stateParam := parsedURL.Query().Get("state")
		require.NotEmpty(t, stateParam, "State parameter should be present")

		// State format: "browser:" prefix followed by signed token
		// We verify structure but not internal format (that's implementation detail)
		assert.True(t, strings.HasPrefix(stateParam, "browser:"), "State should start with browser:")
		assert.Greater(t, len(stateParam), len("browser:"), "State should have content after prefix")

		// Verify state contains signature (has dot separator indicating signed data)
		stateContent := strings.TrimPrefix(stateParam, "browser:")
		assert.Contains(t, stateContent, ".", "Signed state should contain signature separator")
	})

	t.Run("AuthenticatedUserCanAccessTokens", func(t *testing.T) {
		// The client with cookie jar will automatically follow the full SSO flow:
		// 1. GET /my/tokens -> redirect to Google OAuth
		// 2. Google OAuth redirects to /oauth/callback with code
		// 3. Callback sets session cookie and redirects to /my/tokens
		// 4. Client follows redirect with cookie and gets the page

		resp, err := client.Get("http://localhost:8080/my/tokens")
		require.NoError(t, err)
		defer resp.Body.Close()

		// After following all redirects, we should be at /my/tokens with 200 OK
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Should access /my/tokens after SSO")
		finalURL := resp.Request.URL.String()
		assert.Contains(t, finalURL, "/my/tokens", "Should end up at /my/tokens after SSO")

		// Read response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		bodyStr := string(body)

		// Should show both services without tokens
		assert.Contains(t, bodyStr, "Notion", "Expected Notion service in response")
		assert.Contains(t, bodyStr, "GitHub", "Expected GitHub service in response")
	})

	t.Run("SetTokenWithValidation", func(t *testing.T) {
		// Assume we're already authenticated from previous test
		// Get CSRF token first
		resp, err := client.Get("http://localhost:8080/my/tokens")
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Extract CSRF token from response
		csrfToken := extractCSRFToken(t, string(body))

		// Try to set invalid Notion token
		form := url.Values{
			"service":    []string{"notion"},
			"token":      []string{"invalid-token"},
			"csrf_token": []string{csrfToken},
		}

		req, _ := http.NewRequest("POST", "http://localhost:8080/my/tokens/set", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Use custom client that doesn't follow redirects for this test
		noRedirectClient := &http.Client{
			Jar: jar, // Use same cookie jar
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err = noRedirectClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect with error
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode, "Expected redirect")
		location := resp.Header.Get("Location")
		assert.Contains(t, location, "error", "Expected error in redirect")

		// Get new CSRF token
		resp, err = client.Get("http://localhost:8080/my/tokens")
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		csrfToken = extractCSRFToken(t, string(body))

		// Set valid Notion token (regex expects exactly 43 chars after "secret_")
		form = url.Values{
			"service":    {"notion"},
			"token":      {"secret_1234567890123456789012345678901234567890123"},
			"csrf_token": {csrfToken},
		}

		req, _ = http.NewRequest("POST", "http://localhost:8080/my/tokens/set", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err = noRedirectClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should redirect with success
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode, "Expected redirect")
		location = resp.Header.Get("Location")
		assert.Contains(t, location, "success", "Expected success in redirect")
	})
}

// TestStateParameterHandling tests OAuth state parameter requirements
func TestStateParameterHandling(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		state       string
		expectError bool
	}{
		{"Production without state", "production", "", true},
		{"Production with state", "production", "secure-random-state", false},
		{"Development without state", "development", "", false}, // Should auto-generate
		{"Development with state", "development", "test-state", false},
	}

	for _, tt := range tests {
		// capture range variable
		t.Run(tt.name, func(t *testing.T) {
			// Start server with specific environment
			mcpCmd := startOAuthServer(t, map[string]string{
				"MCP_FRONT_ENV": tt.environment,
			})
			defer stopServer(mcpCmd)

			if !waitForHealthCheck(10) {
				t.Fatal("Server failed to start")
			}

			// Register a client first
			clientID := registerTestClient(t)

			// Create authorization request
			params := url.Values{
				"response_type":         {"code"},
				"client_id":             {clientID},
				"redirect_uri":          {"http://127.0.0.1:6274/oauth/callback"},
				"code_challenge":        {"test-challenge"},
				"code_challenge_method": {"S256"},
				"scope":                 {"read write"},
			}
			if tt.state != "" {
				params.Set("state", tt.state)
			}

			authURL := fmt.Sprintf("http://localhost:8080/authorize?%s", params.Encode())

			// Use a client that doesn't follow redirects
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Get(authURL)
			if err != nil {
				t.Fatalf("Authorization request failed: %v", err)
			}
			defer resp.Body.Close()

			if tt.expectError {
				// OAuth errors are returned as redirects with error parameters
				if resp.StatusCode == 302 || resp.StatusCode == 303 {
					location := resp.Header.Get("Location")
					if strings.Contains(location, "error=") {
					} else {
						t.Errorf("Expected error redirect for %s, got redirect without error", tt.name)
					}
				} else if resp.StatusCode >= 400 {
				} else {
					t.Errorf("Expected error for %s, got status %d", tt.name, resp.StatusCode)
				}
			} else {
				if resp.StatusCode == 302 || resp.StatusCode == 303 {
					location := resp.Header.Get("Location")
					if strings.Contains(location, "error=") {
						t.Errorf("Unexpected error redirect for %s: %s", tt.name, location)
					}
				} else if resp.StatusCode < 400 {
				} else {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Expected success for %s, got status %d: %s", tt.name, resp.StatusCode, string(body))
				}
			}
		})
	}
}

// TestEnvironmentModes tests development vs production mode differences
func TestEnvironmentModes(t *testing.T) {
	t.Run("DevelopmentMode", func(t *testing.T) {
		mcpCmd := startOAuthServer(t, map[string]string{
			"MCP_FRONT_ENV": "development",
		})
		defer stopServer(mcpCmd)

		if !waitForHealthCheck(30) {
			t.Fatal("Server failed to start")
		}

		// In development mode, missing state should be auto-generated
		clientID := registerTestClient(t)

		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://127.0.0.1:6274/oauth/callback"},
			"code_challenge":        {"test-challenge"},
			"code_challenge_method": {"S256"},
			"scope":                 {"read"},
			// Intentionally omitting state parameter
		}

		// Use a client that doesn't follow redirects
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Get("http://localhost:8080/authorize?" + params.Encode())
		if err != nil {
			t.Fatalf("Failed to make auth request: %v", err)
		}
		defer resp.Body.Close()

		// Should redirect (302) not error
		if resp.StatusCode >= 400 && resp.StatusCode != 302 {
			t.Errorf("Development mode should handle missing state, got status %d", resp.StatusCode)
		}
	})

	t.Run("ProductionMode", func(t *testing.T) {
		mcpCmd := startOAuthServer(t, map[string]string{
			"MCP_FRONT_ENV": "production",
		})
		defer stopServer(mcpCmd)

		if !waitForHealthCheck(30) {
			t.Fatal("Server failed to start")
		}

		// In production mode, state should be required
		clientID := registerTestClient(t)

		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://127.0.0.1:6274/oauth/callback"},
			"code_challenge":        {"test-challenge"},
			"code_challenge_method": {"S256"},
			"scope":                 {"read"},
			// Intentionally omitting state parameter
		}

		// Use a client that doesn't follow redirects
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Get("http://localhost:8080/authorize?" + params.Encode())
		if err != nil {
			t.Fatalf("Failed to make auth request: %v", err)
		}
		defer resp.Body.Close()

		// Should error - OAuth errors are returned as redirects
		if resp.StatusCode == 302 || resp.StatusCode == 303 {
			location := resp.Header.Get("Location")
			if strings.Contains(location, "error=") {
			} else {
				t.Errorf("Expected error redirect in production mode, got redirect without error")
			}
		} else if resp.StatusCode >= 400 {
		} else {
			t.Errorf("Production mode should require state parameter, got status %d", resp.StatusCode)
		}
	})
}

// TestOAuthEndpoints tests all OAuth endpoints comprehensively
func TestOAuthEndpoints(t *testing.T) {
	mcpCmd := startOAuthServer(t, map[string]string{
		"MCP_FRONT_ENV": "development",
	})
	defer stopServer(mcpCmd)

	if !waitForHealthCheck(10) {
		t.Fatal("Server failed to start")
	}

	t.Run("Discovery", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatalf("Discovery request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("Discovery failed with status %d", resp.StatusCode)
		}

		var discovery map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
			t.Fatalf("Failed to decode discovery response: %v", err)
		}

		// Verify all required fields
		required := []string{
			"issuer",
			"authorization_endpoint",
			"token_endpoint",
			"registration_endpoint",
			"response_types_supported",
			"grant_types_supported",
			"code_challenge_methods_supported",
		}

		for _, field := range required {
			if _, ok := discovery[field]; !ok {
				t.Errorf("Missing required discovery field: %s", field)
			}
		}

	})

	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/health")
		if err != nil {
			t.Fatalf("Health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Health check should return 200, got %d", resp.StatusCode)
		}

		var health map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
			t.Fatalf("Failed to decode health response: %v", err)
		}
		if health["status"] != "ok" {
			t.Errorf("Expected status 'ok', got '%s'", health["status"])
		}

	})
}

// TestCORSHeaders tests CORS headers for Claude.ai compatibility
func TestCORSHeaders(t *testing.T) {
	mcpCmd := startOAuthServer(t, map[string]string{
		"MCP_FRONT_ENV": "development",
	})
	defer stopServer(mcpCmd)

	if !waitForHealthCheck(10) {
		t.Fatal("Server failed to start")
	}

	// Test preflight request
	req, _ := http.NewRequest("OPTIONS", "http://localhost:8080/register", nil)
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Preflight request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Preflight should return 200, got %d", resp.StatusCode)
	}

	// Check CORS headers
	expectedHeaders := map[string]string{
		"Access-Control-Allow-Origin":  "https://claude.ai",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization, Cache-Control, mcp-protocol-version",
	}

	for header, expected := range expectedHeaders {
		actual := resp.Header.Get(header)
		if actual != expected {
			t.Errorf("Expected %s: '%s', got '%s'", header, expected, actual)
		}
	}

}

// TestToolAdvertisementWithUserTokens tests that tools are advertised even without user tokens
// but fail gracefully when invoked without the required token, and succeed with the token
func TestToolAdvertisementWithUserTokens(t *testing.T) {
	// Start OAuth server with user token configuration
	startMCPFront(t, "config/config.oauth-usertoken-tools-test.json",
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-oauth",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
		"MCP_FRONT_ENV=development",
		"LOG_LEVEL=debug",
	)

	if !waitForHealthCheck(30) {
		t.Fatal("Server failed to start")
	}

	// Complete OAuth flow to get a valid access token
	accessToken := getOAuthAccessToken(t, "http://localhost:8080/postgres")

	t.Run("ToolsAdvertisedWithoutToken", func(t *testing.T) {
		// Create MCP client with OAuth token
		mcpClient := NewMCPSSEClient("http://localhost:8080")
		mcpClient.SetAuthToken(accessToken)

		// Connect to postgres SSE endpoint
		err := mcpClient.Connect()
		require.NoError(t, err, "Should connect to postgres SSE endpoint without user token")
		defer mcpClient.Close()

		// Request tools list
		toolsResp, err := mcpClient.SendMCPRequest("tools/list", map[string]any{})
		require.NoError(t, err, "Should list tools without user token")

		// Verify we got tools
		resultMap, ok := toolsResp["result"].(map[string]any)
		require.True(t, ok, "Expected result in tools response")

		tools, ok := resultMap["tools"].([]any)
		require.True(t, ok, "Expected tools array in result")
		assert.NotEmpty(t, tools, "Should have tools advertised")

		// Check for common postgres tools
		var toolNames []string
		for _, tool := range tools {
			if toolMap, ok := tool.(map[string]any); ok {
				if name, ok := toolMap["name"].(string); ok {
					toolNames = append(toolNames, name)
				}
			}
		}

		assert.Contains(t, toolNames, "query", "Should have query tool")
		t.Logf("Successfully advertised tools without user token: %v", toolNames)
	})

	t.Run("ToolInvocationFailsWithoutToken", func(t *testing.T) {
		// Create MCP client with OAuth token
		mcpClient := NewMCPSSEClient("http://localhost:8080")
		mcpClient.SetAuthToken(accessToken)

		// Connect to postgres SSE endpoint
		err := mcpClient.Connect()
		require.NoError(t, err)
		defer mcpClient.Close()

		// Try to invoke a tool without user token
		queryParams := map[string]any{
			"name": "query",
			"arguments": map[string]any{
				"sql": "SELECT 1",
			},
		}

		result, err := mcpClient.SendMCPRequest("tools/call", queryParams)
		require.NoError(t, err, "Should get response even without token")

		// MCP protocol returns errors as successful responses with error content
		require.NotNil(t, result["result"], "Should have result in response")

		resultMap := result["result"].(map[string]any)
		content := resultMap["content"].([]any)
		require.NotEmpty(t, content, "Should have content in result")

		contentItem := content[0].(map[string]any)
		errorJSON := contentItem["text"].(string)

		// Parse the error JSON
		var errorData map[string]any
		err = json.Unmarshal([]byte(errorJSON), &errorData)
		require.NoError(t, err, "Error should be valid JSON")

		// Verify error structure
		errorInfo := errorData["error"].(map[string]any)
		assert.Equal(t, "token_required", errorInfo["code"], "Error code should be token_required")

		errorMessage := errorInfo["message"].(string)
		assert.Contains(t, errorMessage, "token required", "Error should mention token required")
		assert.Contains(t, errorMessage, "/my/tokens", "Error should mention token setup URL")
		assert.Contains(t, errorMessage, "Test Service", "Error should mention service name")

		// Verify error data
		errData := errorInfo["data"].(map[string]any)
		assert.Equal(t, "postgres", errData["service"], "Should identify the service")
		assert.Contains(t, errData["tokenSetupUrl"].(string), "/my/tokens", "Should include token setup URL")

		// Verify instructions
		instructions := errData["instructions"].(map[string]any)
		assert.Contains(t, instructions["ai"].(string), "CRITICAL", "Should have AI instructions")
		assert.Contains(t, instructions["human"].(string), "token required", "Should have human instructions")
	})

	t.Run("ToolInvocationSucceedsWithUserToken", func(t *testing.T) {
		// Step 1: GET /my/tokens to extract CSRF token
		jar, err := cookiejar.New(nil)
		require.NoError(t, err)
		client := &http.Client{
			Jar: jar, // Need cookie jar for CSRF
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		}

		req, err := http.NewRequest("GET", "http://localhost:8080/my/tokens", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check if we got the page or a redirect
		if resp.StatusCode == 302 || resp.StatusCode == 303 {
			// Follow the redirect
			location := resp.Header.Get("Location")
			t.Logf("Got redirect to: %s", location)

			// Allow redirects for this request
			client = &http.Client{
				Jar: jar,
			}

			req, err = http.NewRequest("GET", "http://localhost:8080/my/tokens", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+accessToken)

			resp, err = client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
		}

		require.Equal(t, 200, resp.StatusCode, "Should be able to access token page")

		// Extract CSRF token from HTML
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Look for the CSRF token in the form
		csrfRegex := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
		matches := csrfRegex.FindSubmatch(body)
		require.Len(t, matches, 2, "Should find CSRF token in form")
		csrfToken := string(matches[1])

		// Step 2: POST to /my/tokens/set with test token
		formData := url.Values{
			"service":    {"postgres"},
			"token":      {"test-user-token-12345"},
			"csrf_token": {csrfToken},
		}

		req, err = http.NewRequest("POST", "http://localhost:8080/my/tokens/set", strings.NewReader(formData.Encode()))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check the response - it might be 200 if following redirects
		switch resp.StatusCode {
		case 200:
			// That's fine, it means the token was set and we got the page back
			t.Log("Token set successfully, got page response")
		case 302, 303:
			// Also fine, redirect means success
			t.Log("Token set successfully, got redirect")
		default:
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Unexpected response setting token: status=%d, body=%s", resp.StatusCode, string(body))
		}

		// Step 3: Now test tool invocation with the token
		mcpClient := NewMCPSSEClient("http://localhost:8080")
		mcpClient.SetAuthToken(accessToken)

		err = mcpClient.Connect()
		require.NoError(t, err, "Should connect to postgres SSE endpoint")
		defer mcpClient.Close()

		// Call the query tool with a simple query
		queryParams := map[string]any{
			"name": "query",
			"arguments": map[string]any{
				"sql": "SELECT 1 as test",
			},
		}

		result, err := mcpClient.SendMCPRequest("tools/call", queryParams)
		require.NoError(t, err, "Should successfully call tool with token")

		// Verify we got a successful result, not an error
		require.NotNil(t, result["result"], "Should have result in response")

		resultMap := result["result"].(map[string]any)
		content := resultMap["content"].([]any)
		require.NotEmpty(t, content, "Should have content in result")

		contentItem := content[0].(map[string]any)
		resultText := contentItem["text"].(string)

		// The result should contain actual query results, not an error
		assert.NotContains(t, resultText, "token_required", "Should not have token error")
		assert.NotContains(t, resultText, "Token Required", "Should not have token error message")

		// Postgres query result should contain our test value
		assert.Contains(t, resultText, "1", "Should contain query result")

		t.Log("Successfully invoked tool with user token")
	})
}

// Helper functions

func startOAuthServer(t *testing.T, env map[string]string) *exec.Cmd {
	// Start with OAuth config
	mcpCmd := exec.Command("../cmd/mcp-front/mcp-front", "-config", "config/config.oauth-test.json")

	// Set default environment
	mcpCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-oauth",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	}

	// Override with provided env
	for key, value := range env {
		mcpCmd.Env = append(mcpCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Capture stderr for debugging and also output to test log
	var stderr bytes.Buffer
	mcpCmd.Stderr = io.MultiWriter(&stderr, os.Stderr)

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start OAuth server: %v", err)
	}

	// Give a moment for immediate failures
	time.Sleep(100 * time.Millisecond)

	// Check if process died immediately
	if mcpCmd.ProcessState != nil {
		t.Fatalf("OAuth server died immediately: %s", stderr.String())
	}

	return mcpCmd
}

// startOAuthServerWithTokenConfig starts the OAuth server with user token configuration
func startOAuthServerWithTokenConfig(t *testing.T) *exec.Cmd {
	// Start with user token config
	mcpCmd := exec.Command("../cmd/mcp-front/mcp-front", "-config", "config/config.oauth-token-test.json")

	// Set default environment
	mcpCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-oauth",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
		"MCP_FRONT_ENV=development",
	}

	// Capture stderr for debugging and also output to test log
	var stderr bytes.Buffer
	mcpCmd.Stderr = io.MultiWriter(&stderr, os.Stderr)

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start OAuth server: %v", err)
	}

	// Give a moment for immediate failures
	time.Sleep(100 * time.Millisecond)

	// Check if process died immediately
	if mcpCmd.ProcessState != nil {
		t.Fatalf("OAuth server died immediately: %s", stderr.String())
	}

	return mcpCmd
}

func stopServer(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		// Give the OS time to release the port
		time.Sleep(100 * time.Millisecond)
	}
}

func waitForHealthCheck(seconds int) bool {
	for range seconds {
		if checkHealth() {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func checkHealth() bool {
	resp, err := http.Get("http://localhost:8080/health")
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return true
	}
	if resp != nil {
		resp.Body.Close()
	}
	return false
}

func registerTestClient(t *testing.T) string {
	clientReq := map[string]any{
		"redirect_uris": []string{"http://127.0.0.1:6274/oauth/callback"},
		"scope":         "openid email profile read write",
	}

	body, _ := json.Marshal(clientReq)
	resp, err := http.Post(
		"http://localhost:8080/register",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Client registration failed: %d - %s", resp.StatusCode, string(body))
	}

	var clientResp map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&clientResp)
	return clientResp["client_id"].(string)
}

// extractCSRFToken extracts the CSRF token from the HTML response
func extractCSRFToken(t *testing.T, html string) string {
	// Look for <input type="hidden" name="csrf_token" value="...">
	re := regexp.MustCompile(`<input[^>]+name="csrf_token"[^>]+value="([^"]+)"`)
	matches := re.FindStringSubmatch(html)
	require.GreaterOrEqual(t, len(matches), 2, "CSRF token not found in response")
	return matches[1]
}

// contains is a simple helper to check if string contains substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// TestServiceOAuthIntegration validates the complete OAuth flow for external services
func TestServiceOAuthIntegration(t *testing.T) {
	// Start fake service OAuth provider on port 9091
	fakeService := NewFakeServiceOAuthServer("9091")
	err := fakeService.Start()
	require.NoError(t, err)
	defer func() { _ = fakeService.Stop() }()

	// Start mcp-front with OAuth service configuration
	startMCPFront(t, "config/config.oauth-service-integration-test.json",
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-oauth",
		"TEST_SERVICE_CLIENT_ID=service-client-id",
		"TEST_SERVICE_CLIENT_SECRET=service-client-secret",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
		"MCP_FRONT_ENV=development",
	)

	if !waitForHealthCheck(30) {
		t.Fatal("Server failed to start")
	}

	// For this test, we use browser SSO instead of OAuth client flow
	// This simulates a user in the browser connecting services
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Complete Google OAuth to get browser session
	// Access /my/tokens which triggers SSO flow
	resp, err := client.Get("http://localhost:8080/my/tokens")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should have completed SSO and landed on /my/tokens
	require.Equal(t, http.StatusOK, resp.StatusCode)

	t.Run("ServiceOAuthConnectFlow", func(t *testing.T) {
		// User clicks "Connect" for the service
		req, _ := http.NewRequest("GET", "http://localhost:8080/oauth/connect?service=test-service", nil)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should complete OAuth flow and redirect back with success
		// The http.Client automatically follows redirects:
		// 1. /oauth/connect → redirects to localhost:9091/oauth/authorize
		// 2. Fake service → redirects to /oauth/callback/test-service?code=...
		// 3. Callback → stores token, redirects to /my/tokens with success message

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Final page should show success
		assert.Contains(t, bodyStr, "Successfully connected", "Should show success message after OAuth flow")
		assert.Contains(t, bodyStr, "Test OAuth Service", "Should mention service name")
	})

	t.Run("ConnectedServiceShownOnTokenPage", func(t *testing.T) {
		// After OAuth connection, service should appear as connected
		req, _ := http.NewRequest("GET", "http://localhost:8080/my/tokens", nil)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// Should show the service with connected status
		assert.Contains(t, bodyStr, "Test OAuth Service")
		// OAuth-connected services show disconnect button, not connect
		assert.Contains(t, bodyStr, "Disconnect", "OAuth-connected service should show Disconnect button")
	})
}

// getOAuthAccessToken completes the OAuth flow and returns a valid access token
func getOAuthAccessToken(t *testing.T, resource string) string {
	// Register a test client
	clientID := registerTestClient(t)

	// Generate PKCE challenge (must be at least 43 characters)
	codeVerifier := "test-code-verifier-that-is-at-least-43-characters-long"
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Step 1: Authorization request
	authParams := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://127.0.0.1:6274/oauth/callback"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"openid email profile"},
		"state":                 {"test-state"},
		"resource":              {resource},
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authResp, err := client.Get("http://localhost:8080/authorize?" + authParams.Encode())
	require.NoError(t, err)
	defer authResp.Body.Close()

	// Should redirect to Google OAuth (our mock)
	require.Contains(t, []int{302, 303}, authResp.StatusCode, "Should redirect to Google OAuth")
	location := authResp.Header.Get("Location")
	require.Contains(t, location, "http://localhost:9090/auth", "Should redirect to mock Google OAuth")

	// Parse the redirect to get the state parameter
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)
	_ = redirectURL.Query().Get("state") // state is included in the redirect but not needed for this test

	// Step 2: Follow redirect to mock Google OAuth (which immediately redirects back)
	googleResp, err := client.Get(location)
	require.NoError(t, err)
	defer googleResp.Body.Close()

	// Mock Google OAuth redirects back to callback
	require.Contains(t, []int{302, 303}, googleResp.StatusCode, "Mock Google should redirect back")
	callbackLocation := googleResp.Header.Get("Location")
	require.Contains(t, callbackLocation, "/oauth/callback", "Should redirect to callback")

	// Step 3: Follow callback redirect
	callbackResp, err := client.Get(callbackLocation)
	require.NoError(t, err)
	defer callbackResp.Body.Close()

	// Should redirect to the original redirect_uri with authorization code
	require.Contains(t, []int{302, 303}, callbackResp.StatusCode, "Callback should redirect with code")
	finalLocation := callbackResp.Header.Get("Location")

	// Parse authorization code from final redirect
	finalURL, err := url.Parse(finalLocation)
	require.NoError(t, err)
	authCode := finalURL.Query().Get("code")
	require.NotEmpty(t, authCode, "Should have authorization code")

	// Step 4: Exchange code for token
	tokenParams := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {"http://127.0.0.1:6274/oauth/callback"},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}

	tokenResp, err := http.PostForm("http://localhost:8080/token", tokenParams)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Logf("Token exchange failed with status %d: %s", tokenResp.StatusCode, string(body))
	}

	require.Equal(t, 200, tokenResp.StatusCode, "Token exchange should succeed")

	var tokenData map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenData)
	require.NoError(t, err)

	accessToken := tokenData["access_token"].(string)
	require.NotEmpty(t, accessToken, "Should have access token")

	return accessToken
}

// MockUserTokenStore mocks the UserTokenStore interface for testing
type MockUserTokenStore struct {
	mock.Mock
}

func (m *MockUserTokenStore) GetUserToken(ctx context.Context, email, service string) (string, error) {
	args := m.Called(ctx, email, service)
	return args.String(0), args.Error(1)
}

func (m *MockUserTokenStore) SetUserToken(ctx context.Context, email, service, token string) error {
	args := m.Called(ctx, email, service, token)
	return args.Error(0)
}

func (m *MockUserTokenStore) DeleteUserToken(ctx context.Context, email, service string) error {
	args := m.Called(ctx, email, service)
	return args.Error(0)
}

func (m *MockUserTokenStore) ListUserServices(ctx context.Context, email string) ([]string, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// TestRFC8707ResourceIndicators validates RFC 8707 resource indicator functionality
func TestRFC8707ResourceIndicators(t *testing.T) {
	startMCPFront(t, "config/config.oauth-rfc8707-test.json",
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
		"GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth",
		"GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token",
		"GOOGLE_USERINFO_URL=http://localhost:9090/userinfo",
	)

	waitForMCPFront(t)

	t.Run("BaseProtectedResourceMetadataReturns404", func(t *testing.T) {
		// Base metadata endpoint should return 404, directing clients to per-service endpoints
		resp, err := http.Get("http://localhost:8080/.well-known/oauth-protected-resource")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 404, resp.StatusCode, "Base protected resource metadata endpoint should return 404")

		var errResp map[string]any
		err = json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)

		assert.Contains(t, errResp["message"], "per-service", "Error message should direct to per-service endpoints")
	})

	t.Run("PerServiceProtectedResourceMetadataEndpoint", func(t *testing.T) {
		// Per-service metadata endpoint should return service-specific resource URI
		resp, err := http.Get("http://localhost:8080/.well-known/oauth-protected-resource/test-sse")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode, "Per-service protected resource metadata endpoint should exist")

		var metadata map[string]any
		err = json.NewDecoder(resp.Body).Decode(&metadata)
		require.NoError(t, err)

		// Resource should be service-specific, not base URL
		assert.Equal(t, "http://localhost:8080/test-sse", metadata["resource"],
			"Resource should be service-specific URL")

		authzServers, ok := metadata["authorization_servers"].([]any)
		require.True(t, ok, "Should have authorization_servers array")
		require.NotEmpty(t, authzServers)
		assert.Equal(t, "http://localhost:8080", authzServers[0],
			"Authorization server should be base issuer")
	})

	t.Run("UnknownServiceReturns404", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/.well-known/oauth-protected-resource/nonexistent-service")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 404, resp.StatusCode, "Unknown service should return 404")
	})

	t.Run("TokenWithResourceParameter", func(t *testing.T) {
		clientID := registerTestClient(t)

		codeVerifier := "test-code-verifier-that-is-at-least-43-characters-long"
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

		authParams := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {"http://127.0.0.1:6274/oauth/callback"},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"scope":                 {"openid email profile"},
			"state":                 {"test-state"},
			"resource":              {"http://localhost:8080/test-sse"},
		}

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		authResp, err := client.Get("http://localhost:8080/authorize?" + authParams.Encode())
		require.NoError(t, err)
		defer authResp.Body.Close()

		assert.Contains(t, []int{302, 303}, authResp.StatusCode, "Should redirect to Google OAuth")

		location := authResp.Header.Get("Location")
		googleResp, err := client.Get(location)
		require.NoError(t, err)
		defer googleResp.Body.Close()

		callbackLocation := googleResp.Header.Get("Location")
		callbackResp, err := client.Get(callbackLocation)
		require.NoError(t, err)
		defer callbackResp.Body.Close()

		finalURL, err := url.Parse(callbackResp.Header.Get("Location"))
		require.NoError(t, err)
		authCode := finalURL.Query().Get("code")
		require.NotEmpty(t, authCode, "Should have authorization code")

		tokenParams := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {"http://127.0.0.1:6274/oauth/callback"},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		}

		tokenResp, err := http.PostForm("http://localhost:8080/token", tokenParams)
		require.NoError(t, err)
		defer tokenResp.Body.Close()

		require.Equal(t, 200, tokenResp.StatusCode, "Token exchange should succeed")

		var tokenData map[string]any
		err = json.NewDecoder(tokenResp.Body).Decode(&tokenData)
		require.NoError(t, err)

		testSSEToken := tokenData["access_token"].(string)
		require.NotEmpty(t, testSSEToken, "Should have access token")

		t.Logf("Got token with test-sse audience: %s", testSSEToken[:20]+"...")

		// Verify token works for test-sse (matching audience)
		req, _ := http.NewRequest("GET", "http://localhost:8080/test-sse/sse", nil)
		req.Header.Set("Authorization", "Bearer "+testSSEToken)
		req.Header.Set("Accept", "text/event-stream")

		sseResp, err := client.Do(req)
		require.NoError(t, err)
		defer sseResp.Body.Close()

		assert.Equal(t, 200, sseResp.StatusCode,
			"Token with test-sse audience should access /test-sse/sse")

		// Verify token does NOT work for test-streamable (wrong audience)
		req, _ = http.NewRequest("GET", "http://localhost:8080/test-streamable/sse", nil)
		req.Header.Set("Authorization", "Bearer "+testSSEToken)
		req.Header.Set("Accept", "text/event-stream")

		streamableResp, err := client.Do(req)
		require.NoError(t, err)
		defer streamableResp.Body.Close()

		assert.Equal(t, 401, streamableResp.StatusCode,
			"Token with test-sse audience should NOT access /test-streamable/sse")

		wwwAuth := streamableResp.Header.Get("WWW-Authenticate")
		assert.Contains(t, wwwAuth, "Bearer resource_metadata=",
			"401 response should include RFC 9728 WWW-Authenticate header")
		// Per RFC 9728 Section 5.2, the metadata URI should be service-specific
		assert.Contains(t, wwwAuth, "/.well-known/oauth-protected-resource/test-streamable",
			"401 response should point to per-service metadata endpoint")
	})

	t.Run("401ResponseIncludesServiceSpecificMetadataURI", func(t *testing.T) {
		// Request to a protected endpoint without token should get 401
		// with service-specific metadata URI in WWW-Authenticate header
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req, _ := http.NewRequest("GET", "http://localhost:8080/test-sse/sse", nil)
		req.Header.Set("Accept", "text/event-stream")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 401, resp.StatusCode, "Request without token should return 401")

		wwwAuth := resp.Header.Get("WWW-Authenticate")
		assert.Contains(t, wwwAuth, "Bearer resource_metadata=",
			"401 response should include RFC 9728 WWW-Authenticate header")
		assert.Contains(t, wwwAuth, "/.well-known/oauth-protected-resource/test-sse",
			"401 response should point to test-sse specific metadata endpoint")
	})
}
