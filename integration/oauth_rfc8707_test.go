package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRFC8707ResourceIndicators validates RFC 8707 resource indicator functionality
func TestRFC8707ResourceIndicators(t *testing.T) {
	startMCPFront(t, "config/config.oauth-rfc8707-test.json",
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
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
