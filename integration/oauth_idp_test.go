package integration

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idpEnvGitHub is the set of env vars needed for GitHub IDP integration tests.
var idpEnvGitHub = []string{
	"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
	"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
	"GITHUB_CLIENT_SECRET=test-github-client-secret",
	"MCP_FRONT_ENV=development",
}

// idpEnvOIDC is the set of env vars needed for OIDC IDP integration tests.
var idpEnvOIDC = []string{
	"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
	"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
	"OIDC_CLIENT_SECRET=test-oidc-client-secret",
	"MCP_FRONT_ENV=development",
}

// idpEnvAzure is the set of env vars needed for Azure IDP integration tests.
var idpEnvAzure = []string{
	"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
	"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
	"AZURE_CLIENT_SECRET=test-azure-client-secret",
	"MCP_FRONT_ENV=development",
}

// TestGitHubOAuthFlow tests the full OAuth flow using the GitHub IDP.
func TestGitHubOAuthFlow(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-github-test",
		testGitHubOAuthConfig("test-org"),
		map[string]any{"postgres": testPostgresServer()},
	)
	startMCPFront(t, writeTestConfig(t, cfg), idpEnvGitHub...)
	waitForMCPFront(t)

	accessToken := getOAuthAccessTokenForIDP(t, "http://localhost:8080/postgres", "localhost:9092")

	mcpClient := NewMCPSSEClient("http://localhost:8080")
	mcpClient.SetAuthToken(accessToken)

	err := mcpClient.Connect()
	require.NoError(t, err, "Should connect to postgres with GitHub-issued token")
	defer mcpClient.Close()

	toolsResp, err := mcpClient.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err, "Should list tools with GitHub-issued token")

	resultMap, ok := toolsResp["result"].(map[string]any)
	require.True(t, ok, "Expected result in tools response")
	tools, ok := resultMap["tools"].([]any)
	require.True(t, ok, "Expected tools array")
	assert.NotEmpty(t, tools, "Should have tools")
}

// TestGitHubOrgDenial verifies that users not in allowed orgs are denied.
func TestGitHubOrgDenial(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-github-org-deny",
		testGitHubOAuthConfig("org-that-doesnt-match"),
		map[string]any{"postgres": testPostgresServer()},
	)
	startMCPFront(t, writeTestConfig(t, cfg), idpEnvGitHub...)
	waitForMCPFront(t)

	// Register client and start auth flow
	clientID := registerTestClient(t)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Authorize
	authResp, err := client.Get("http://localhost:8080/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=http://127.0.0.1:6274/oauth/callback&code_challenge=test-challenge&code_challenge_method=S256" +
		"&scope=openid+email+profile&state=test-state&resource=http://localhost:8080/postgres")
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{302, 303}, authResp.StatusCode)

	// Step 2: Follow to GitHub fake
	location := authResp.Header.Get("Location")
	idpResp, err := client.Get(location)
	require.NoError(t, err)
	defer idpResp.Body.Close()

	// Step 3: Follow callback — should get an error (access denied), not a code
	callbackLocation := idpResp.Header.Get("Location")
	callbackResp, err := client.Get(callbackLocation)
	require.NoError(t, err)
	defer callbackResp.Body.Close()

	// The callback should either:
	// - Return a 403 directly, or
	// - Redirect to the redirect_uri with an error parameter
	if callbackResp.StatusCode == 302 || callbackResp.StatusCode == 303 {
		finalLocation := callbackResp.Header.Get("Location")
		assert.Contains(t, finalLocation, "error=", "Should redirect with error for org denial")
	} else {
		// Direct error response
		body, _ := io.ReadAll(callbackResp.Body)
		assert.Contains(t, string(body), "denied", "Should contain denial message")
	}
}

// TestOIDCOAuthFlow tests the full OAuth flow using a generic OIDC provider.
func TestOIDCOAuthFlow(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-oidc-test",
		testOIDCOAuthConfig(),
		map[string]any{"postgres": testPostgresServer()},
	)
	startMCPFront(t, writeTestConfig(t, cfg), idpEnvOIDC...)
	waitForMCPFront(t)

	accessToken := getOAuthAccessTokenForIDP(t, "http://localhost:8080/postgres", "localhost:9093")

	mcpClient := NewMCPSSEClient("http://localhost:8080")
	mcpClient.SetAuthToken(accessToken)

	err := mcpClient.Connect()
	require.NoError(t, err, "Should connect to postgres with OIDC-issued token")
	defer mcpClient.Close()

	toolsResp, err := mcpClient.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err, "Should list tools with OIDC-issued token")

	resultMap, ok := toolsResp["result"].(map[string]any)
	require.True(t, ok, "Expected result in tools response")
	tools, ok := resultMap["tools"].([]any)
	require.True(t, ok, "Expected tools array")
	assert.NotEmpty(t, tools, "Should have tools")
}

// TestAzureOAuthFlow tests the full OAuth flow using the Azure IDP (backed by the OIDC fake server).
func TestAzureOAuthFlow(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-azure-test",
		testAzureOAuthConfig(),
		map[string]any{"postgres": testPostgresServer()},
	)
	startMCPFront(t, writeTestConfig(t, cfg), idpEnvAzure...)
	waitForMCPFront(t)

	accessToken := getOAuthAccessTokenForIDP(t, "http://localhost:8080/postgres", "localhost:9093")

	mcpClient := NewMCPSSEClient("http://localhost:8080")
	mcpClient.SetAuthToken(accessToken)

	err := mcpClient.Connect()
	require.NoError(t, err, "Should connect to postgres with Azure-issued token")
	defer mcpClient.Close()

	toolsResp, err := mcpClient.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err, "Should list tools with Azure-issued token")

	resultMap, ok := toolsResp["result"].(map[string]any)
	require.True(t, ok, "Expected result in tools response")
	tools, ok := resultMap["tools"].([]any)
	require.True(t, ok, "Expected tools array")
	assert.NotEmpty(t, tools, "Should have tools")
}

// TestIDPDomainDenial verifies that domain restrictions are enforced across providers.
func TestIDPDomainDenial(t *testing.T) {
	tests := []struct {
		name       string
		authConfig map[string]any
		env        []string
		idpHost    string
	}{
		{
			name: "GitHub",
			authConfig: func() map[string]any {
				cfg := testGitHubOAuthConfig("test-org")
				cfg["allowedDomains"] = []string{"wrong-domain.com"}
				return cfg
			}(),
			env:     idpEnvGitHub,
			idpHost: "localhost:9092",
		},
		{
			name: "OIDC",
			authConfig: func() map[string]any {
				cfg := testOIDCOAuthConfig()
				cfg["allowedDomains"] = []string{"wrong-domain.com"}
				return cfg
			}(),
			env:     idpEnvOIDC,
			idpHost: "localhost:9093",
		},
		{
			name: "Azure",
			authConfig: func() map[string]any {
				cfg := testAzureOAuthConfig()
				cfg["allowedDomains"] = []string{"wrong-domain.com"}
				return cfg
			}(),
			env:     idpEnvAzure,
			idpHost: "localhost:9093",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := buildTestConfig("http://localhost:8080", "mcp-front-domain-deny-"+tt.name,
				tt.authConfig,
				map[string]any{"postgres": testPostgresServer()},
			)
			startMCPFront(t, writeTestConfig(t, cfg), tt.env...)
			waitForMCPFront(t)

			clientID := registerTestClient(t)

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			authResp, err := client.Get("http://localhost:8080/authorize?response_type=code&client_id=" + clientID +
				"&redirect_uri=http://127.0.0.1:6274/oauth/callback&code_challenge=test-challenge&code_challenge_method=S256" +
				"&scope=openid+email+profile&state=test-state&resource=http://localhost:8080/postgres")
			require.NoError(t, err)
			defer authResp.Body.Close()
			require.Contains(t, []int{302, 303}, authResp.StatusCode)

			location := authResp.Header.Get("Location")
			require.Contains(t, location, tt.idpHost, "Should redirect to expected IDP")

			idpResp, err := client.Get(location)
			require.NoError(t, err)
			defer idpResp.Body.Close()

			callbackLocation := idpResp.Header.Get("Location")
			callbackResp, err := client.Get(callbackLocation)
			require.NoError(t, err)
			defer callbackResp.Body.Close()

			if callbackResp.StatusCode == 302 || callbackResp.StatusCode == 303 {
				finalLocation := callbackResp.Header.Get("Location")
				assert.Contains(t, finalLocation, "error=", "Should redirect with error for domain denial")
			} else {
				body, _ := io.ReadAll(callbackResp.Body)
				assert.Contains(t, string(body), "denied", "Should contain denial message")
			}
		})
	}
}
