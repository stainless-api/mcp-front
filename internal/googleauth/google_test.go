package googleauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGoogleAuthURL(t *testing.T) {
	oauthConfig := config.OAuthAuthConfig{
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: config.Secret("test-client-secret"),
		GoogleRedirectURI:  "https://test.example.com/oauth/callback",
	}

	state := "test-state-parameter"
	authURL := GoogleAuthURL(oauthConfig, state)

	// Verify URL structure
	assert.Contains(t, authURL, "https://accounts.google.com/o/oauth2/auth")
	assert.Contains(t, authURL, "client_id=test-client-id")
	assert.Contains(t, authURL, "redirect_uri=https%3A%2F%2Ftest.example.com%2Foauth%2Fcallback")
	assert.Contains(t, authURL, "state=test-state-parameter")
	assert.Contains(t, authURL, "access_type=offline")
	assert.Contains(t, authURL, "prompt=consent")
	assert.Contains(t, authURL, "scope=openid+profile+email")
}

func TestExchangeCodeForToken(t *testing.T) {
	// Create a mock OAuth token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/token", r.URL.Path)

		// Parse form data
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "test-code", r.FormValue("code"))
		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		assert.Equal(t, "test-client-secret", r.FormValue("client_secret"))
		assert.Equal(t, "https://test.example.com/oauth/callback", r.FormValue("redirect_uri"))
		assert.Equal(t, "authorization_code", r.FormValue("grant_type"))

		// Return mock token response
		response := map[string]any{
			"access_token":  "mock-access-token",
			"refresh_token": "mock-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer tokenServer.Close()

	// Set environment variable for custom token URL
	t.Setenv("GOOGLE_OAUTH_TOKEN_URL", tokenServer.URL+"/token")

	oauthConfig := config.OAuthAuthConfig{
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: config.Secret("test-client-secret"),
		GoogleRedirectURI:  "https://test.example.com/oauth/callback",
	}

	token, err := ExchangeCodeForToken(context.Background(), oauthConfig, "test-code")
	require.NoError(t, err)
	require.NotNil(t, token)

	assert.Equal(t, "mock-access-token", token.AccessToken)
	assert.Equal(t, "mock-refresh-token", token.RefreshToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.WithinDuration(t, time.Now().Add(3600*time.Second), token.Expiry, 5*time.Second)
}

func TestValidateUser(t *testing.T) {
	t.Run("valid user in allowed domain", func(t *testing.T) {
		// Create mock user info endpoint
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Contains(t, r.Header.Get("Authorization"), "Bearer mock-token")

			response := UserInfo{
				Email:         "user@example.com",
				HostedDomain:  "example.com",
				Name:          "Test User",
				Picture:       "https://example.com/pic.jpg",
				VerifiedEmail: true,
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}))
		defer userInfoServer.Close()

		t.Setenv("GOOGLE_USERINFO_URL", userInfoServer.URL)

		oauthConfig := config.OAuthAuthConfig{
			AllowedDomains: []string{"example.com", "test.com"},
		}

		token := &oauth2.Token{AccessToken: "mock-token"}
		userInfo, err := ValidateUser(context.Background(), oauthConfig, token)

		require.NoError(t, err)
		assert.Equal(t, "user@example.com", userInfo.Email)
		assert.Equal(t, "example.com", userInfo.HostedDomain)
		assert.Equal(t, "Test User", userInfo.Name)
		assert.True(t, userInfo.VerifiedEmail)
	})

	t.Run("user from disallowed domain", func(t *testing.T) {
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := UserInfo{
				Email:         "user@unauthorized.com",
				HostedDomain:  "unauthorized.com",
				VerifiedEmail: true,
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}))
		defer userInfoServer.Close()

		t.Setenv("GOOGLE_USERINFO_URL", userInfoServer.URL)

		oauthConfig := config.OAuthAuthConfig{
			AllowedDomains: []string{"example.com", "test.com"},
		}

		token := &oauth2.Token{AccessToken: "mock-token"}
		_, err := ValidateUser(context.Background(), oauthConfig, token)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "domain 'unauthorized.com' is not allowed")
	})

	t.Run("no domain restrictions", func(t *testing.T) {
		userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := UserInfo{
				Email:         "user@anydomain.com",
				VerifiedEmail: true,
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}))
		defer userInfoServer.Close()

		t.Setenv("GOOGLE_USERINFO_URL", userInfoServer.URL)

		oauthConfig := config.OAuthAuthConfig{
			AllowedDomains: []string{}, // Empty means allow all
		}

		token := &oauth2.Token{AccessToken: "mock-token"}
		userInfo, err := ValidateUser(context.Background(), oauthConfig, token)

		require.NoError(t, err)
		assert.Equal(t, "user@anydomain.com", userInfo.Email)
	})
}

func TestParseClientRequest(t *testing.T) {
	t.Run("valid request with redirect URIs and scopes", func(t *testing.T) {
		metadata := map[string]any{
			"redirect_uris": []any{
				"https://example.com/callback1",
				"https://example.com/callback2",
			},
			"scope": "read write admin",
		}

		redirectURIs, scopes, err := ParseClientRequest(metadata)
		require.NoError(t, err)

		assert.Equal(t, []string{
			"https://example.com/callback1",
			"https://example.com/callback2",
		}, redirectURIs)
		assert.Equal(t, []string{"read", "write", "admin"}, scopes)
	})

	t.Run("default scopes when not provided", func(t *testing.T) {
		metadata := map[string]any{
			"redirect_uris": []any{"https://example.com/callback"},
		}

		redirectURIs, scopes, err := ParseClientRequest(metadata)
		require.NoError(t, err)

		assert.Equal(t, []string{"https://example.com/callback"}, redirectURIs)
		assert.Equal(t, []string{"read", "write"}, scopes, "Should default to read/write")
	})

	t.Run("empty scope string uses default", func(t *testing.T) {
		metadata := map[string]any{
			"redirect_uris": []any{"https://example.com/callback"},
			"scope":         "   ", // Whitespace only
		}

		_, scopes, err := ParseClientRequest(metadata)
		require.NoError(t, err)

		assert.Equal(t, []string{"read", "write"}, scopes)
	})

	t.Run("missing redirect URIs", func(t *testing.T) {
		metadata := map[string]any{
			"scope": "read write",
		}

		_, _, err := ParseClientRequest(metadata)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid redirect URIs")
	})

	t.Run("empty redirect URIs array", func(t *testing.T) {
		metadata := map[string]any{
			"redirect_uris": []any{},
		}

		_, _, err := ParseClientRequest(metadata)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid redirect URIs")
	})
}
