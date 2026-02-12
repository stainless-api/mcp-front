package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBasicOAuthFlow tests the basic OAuth server functionality
func TestBasicOAuthFlow(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-oauth-test",
		testOAuthConfigFromEnv(),
		map[string]any{"postgres": testPostgresServer()},
	)
	startMCPFront(t, writeTestConfig(t, cfg),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
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
	oauthCfg := buildTestConfig("http://localhost:8080", "mcp-front-oauth-test",
		testOAuthConfigFromEnv(),
		map[string]any{"postgres": testPostgresServer()},
	)
	configPath := writeTestConfig(t, oauthCfg)

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

			mcpCmd := exec.Command("../cmd/mcp-front/mcp-front", "-config", configPath)
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

// Shared helpers for OAuth tests

func startOAuthServer(t *testing.T, env map[string]string) *exec.Cmd {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-oauth-test",
		testOAuthConfigFromEnv(),
		map[string]any{"postgres": testPostgresServer()},
	)
	configPath := writeTestConfig(t, cfg)

	mcpCmd := exec.Command("../cmd/mcp-front/mcp-front", "-config", configPath)

	// Set default environment
	mcpCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-oauth",
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
