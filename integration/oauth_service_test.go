package integration

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
