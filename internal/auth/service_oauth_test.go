package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartOAuthFlow(t *testing.T) {
	store := storage.NewMemoryStorage()
	client := NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))

	serviceConfig := &config.MCPClientConfig{
		RequiresUserToken: true,
		UserAuthentication: &config.UserAuthentication{
			Type:             config.UserAuthTypeOAuth,
			ClientID:         config.Secret("test-client-id"),
			ClientSecret:     config.Secret("test-client-secret"),
			AuthorizationURL: "https://service.example.com/oauth/authorize",
			TokenURL:         "https://service.example.com/oauth/token",
			Scopes:           []string{"read", "write"},
		},
	}

	authURL, err := client.StartOAuthFlow(
		context.Background(),
		"user@example.com",
		"test-service",
		"/my/tokens",
		serviceConfig,
	)

	require.NoError(t, err)
	assert.Contains(t, authURL, "https://service.example.com/oauth/authorize")
	assert.Contains(t, authURL, "client_id=test-client-id")
	assert.Contains(t, authURL, "redirect_uri=https%3A%2F%2Fmcp-front.example.com%2Foauth%2Fcallback%2Ftest-service")
	assert.Contains(t, authURL, "scope=read+write")
	assert.Contains(t, authURL, "state=") // State should be present
}

func TestHandleCallback(t *testing.T) {
	// Create mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// oauth2 library handles the request format, just return tokens
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

	store := storage.NewMemoryStorage()
	client := NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))

	serviceConfig := &config.MCPClientConfig{
		RequiresUserToken: true,
		UserAuthentication: &config.UserAuthentication{
			Type:             config.UserAuthTypeOAuth,
			ClientID:         config.Secret("test-client-id"),
			ClientSecret:     config.Secret("test-client-secret"),
			AuthorizationURL: "https://service.example.com/oauth/authorize",
			TokenURL:         tokenServer.URL,
			Scopes:           []string{"read", "write"},
		},
	}

	// Start flow to get state from URL
	authURL, err := client.StartOAuthFlow(
		context.Background(),
		"user@example.com",
		"test-service",
		"/oauth/services?state=abc",
		serviceConfig,
	)
	require.NoError(t, err)

	// Extract state from authorization URL
	parsedURL, err := url.Parse(authURL)
	require.NoError(t, err)
	state := parsedURL.Query().Get("state")
	require.NotEmpty(t, state)

	// Handle callback
	result, err := client.HandleCallback(
		context.Background(),
		"test-service",
		"test-code",
		state,
		serviceConfig,
	)

	require.NoError(t, err)
	assert.Equal(t, "user@example.com", result.UserEmail)
	assert.Equal(t, "/oauth/services?state=abc", result.ReturnURL)

	// Verify token was stored
	storedToken, err := store.GetUserToken(context.Background(), "user@example.com", "test-service")
	require.NoError(t, err)
	assert.Equal(t, storage.TokenTypeOAuth, storedToken.Type)
	assert.Equal(t, "mock-access-token", storedToken.OAuthData.AccessToken)
	assert.Equal(t, "mock-refresh-token", storedToken.OAuthData.RefreshToken)

}

func TestRefreshToken(t *testing.T) {
	// Create mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "old-refresh-token", r.FormValue("refresh_token"))

		response := map[string]any{
			"access_token":  "new-access-token",
			"refresh_token": "new-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer tokenServer.Close()

	store := storage.NewMemoryStorage()
	client := NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))

	// Store a token expiring in 2 minutes (within our 5-minute refresh threshold)
	// This tests our early refresh logic, not just "can refresh expired tokens"
	oldToken := &storage.StoredToken{
		Type: storage.TokenTypeOAuth,
		OAuthData: &storage.OAuthTokenData{
			AccessToken:  "old-access-token",
			RefreshToken: "old-refresh-token",
			ExpiresAt:    time.Now().Add(2 * time.Minute), // Expires soon, triggers early refresh
			TokenType:    "Bearer",
			Scopes:       []string{"read", "write"},
		},
		UpdatedAt: time.Now(),
	}

	err := store.SetUserToken(context.Background(), "user@example.com", "test-service", oldToken)
	require.NoError(t, err)

	serviceConfig := &config.MCPClientConfig{
		UserAuthentication: &config.UserAuthentication{
			Type:             config.UserAuthTypeOAuth,
			ClientID:         config.Secret("test-client-id"),
			ClientSecret:     config.Secret("test-client-secret"),
			AuthorizationURL: "https://service.example.com/oauth/authorize",
			TokenURL:         tokenServer.URL,
			Scopes:           []string{"read", "write"},
		},
	}

	// Refresh token
	err = client.RefreshToken(
		context.Background(),
		"user@example.com",
		"test-service",
		serviceConfig,
	)

	require.NoError(t, err)

	// Verify token was updated
	refreshedToken, err := store.GetUserToken(context.Background(), "user@example.com", "test-service")
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", refreshedToken.OAuthData.AccessToken)
	assert.Equal(t, "new-refresh-token", refreshedToken.OAuthData.RefreshToken)
}

func TestGetConnectURL(t *testing.T) {
	client := NewServiceOAuthClient(nil, "https://mcp-front.example.com", []byte(strings.Repeat("test-key", 4)))

	t.Run("with return path", func(t *testing.T) {
		url := client.GetConnectURL("my-service", "/my/tokens")
		assert.Equal(t, "https://mcp-front.example.com/oauth/connect?return=%2Fmy%2Ftokens&service=my-service", url)
	})

	t.Run("without return path", func(t *testing.T) {
		url := client.GetConnectURL("my-service", "")
		assert.Equal(t, "https://mcp-front.example.com/oauth/connect?service=my-service", url)
	})
}
