package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

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

// TestToolAdvertisementWithUserTokens tests that tools are advertised even without user tokens
// but fail gracefully when invoked without the required token, and succeed with the token
func TestToolAdvertisementWithUserTokens(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-oauth-usertoken-test",
		testOAuthConfigFromEnv(),
		map[string]any{"postgres": testPostgresServer(withUserToken())},
	)
	startMCPFront(t, writeTestConfig(t, cfg),
		"JWT_SECRET=demo-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-oauth",
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

		assert.Contains(t, toolNames, "execute_sql", "Should have execute_sql tool")
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
			"name": "execute_sql",
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
			"name": "execute_sql",
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

// getOAuthAccessTokenForIDP completes the OAuth flow and returns a valid access token.
// expectedIDPHost is the host:port of the expected IDP redirect target (e.g., "localhost:9090" for Google).
func getOAuthAccessTokenForIDP(t *testing.T, resource, expectedIDPHost string) string {
	t.Helper()

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
		"resource":              {resource},
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Authorization request
	authResp, err := client.Get("http://localhost:8080/authorize?" + authParams.Encode())
	require.NoError(t, err)
	defer authResp.Body.Close()

	require.Contains(t, []int{302, 303}, authResp.StatusCode, "Should redirect to IDP")
	location := authResp.Header.Get("Location")
	require.Contains(t, location, expectedIDPHost, "Should redirect to expected IDP")

	// Step 2: Follow redirect to IDP (which immediately redirects back)
	idpResp, err := client.Get(location)
	require.NoError(t, err)
	defer idpResp.Body.Close()

	require.Contains(t, []int{302, 303}, idpResp.StatusCode, "IDP should redirect back")
	callbackLocation := idpResp.Header.Get("Location")
	require.Contains(t, callbackLocation, "/oauth/callback", "Should redirect to callback")

	// Step 3: Follow callback redirect
	callbackResp, err := client.Get(callbackLocation)
	require.NoError(t, err)
	defer callbackResp.Body.Close()

	require.Contains(t, []int{302, 303}, callbackResp.StatusCode, "Callback should redirect with code")
	finalLocation := callbackResp.Header.Get("Location")

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

// getOAuthAccessToken completes the OAuth flow using the Google IDP and returns a valid access token.
func getOAuthAccessToken(t *testing.T, resource string) string {
	return getOAuthAccessTokenForIDP(t, resource, "localhost:9090")
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
