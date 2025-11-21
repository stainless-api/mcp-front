package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectHandler(t *testing.T) {
	store := storage.NewMemoryStorage()
	oauthClient := auth.NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("k", 32)))

	mcpServers := map[string]*config.MCPClientConfig{
		"test-service": {
			RequiresUserToken: true,
			UserAuthentication: &config.UserAuthentication{
				Type:             config.UserAuthTypeOAuth,
				DisplayName:      "Test Service",
				ClientID:         config.Secret("client-id"),
				ClientSecret:     config.Secret("client-secret"),
				AuthorizationURL: "https://test.example.com/oauth/authorize",
				TokenURL:         "https://test.example.com/oauth/token",
				Scopes:           []string{"read"},
			},
		},
	}

	handlers := NewServiceAuthHandlers(oauthClient, mcpServers, store)

	t.Run("unauthorized without session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/connect?service=test-service", nil)
		rec := httptest.NewRecorder()

		handlers.ConnectHandler(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("redirects to service OAuth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/connect?service=test-service", nil)
		ctx := context.WithValue(req.Context(), oauth.GetUserContextKey(), "user@example.com")
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handlers.ConnectHandler(rec, req)

		assert.Equal(t, http.StatusFound, rec.Code)
		location := rec.Header().Get("Location")
		assert.Contains(t, location, "https://test.example.com/oauth/authorize")
		assert.Contains(t, location, "client_id=client-id")
	})

	t.Run("service not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/connect?service=nonexistent", nil)
		ctx := context.WithValue(req.Context(), oauth.GetUserContextKey(), "user@example.com")
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handlers.ConnectHandler(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("service doesn't support OAuth", func(t *testing.T) {
		handlersNoOAuth := NewServiceAuthHandlers(oauthClient, map[string]*config.MCPClientConfig{
			"no-oauth": {RequiresUserToken: false},
		}, store)

		req := httptest.NewRequest(http.MethodGet, "/oauth/connect?service=no-oauth", nil)
		ctx := context.WithValue(req.Context(), oauth.GetUserContextKey(), "user@example.com")
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handlersNoOAuth.ConnectHandler(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing service parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/connect", nil)
		ctx := context.WithValue(req.Context(), oauth.GetUserContextKey(), "user@example.com")
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handlers.ConnectHandler(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestDisconnectHandler(t *testing.T) {
	store := storage.NewMemoryStorage()
	oauthClient := auth.NewServiceOAuthClient(store, "https://mcp-front.example.com", []byte(strings.Repeat("k", 32)))
	handlers := NewServiceAuthHandlers(oauthClient, map[string]*config.MCPClientConfig{}, store)

	t.Run("unauthorized without session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/disconnect", nil)
		rec := httptest.NewRecorder()

		handlers.DisconnectHandler(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("successfully disconnects service", func(t *testing.T) {
		userEmail := "user@example.com"

		token := &storage.StoredToken{
			Type:      storage.TokenTypeOAuth,
			OAuthData: &storage.OAuthTokenData{AccessToken: "test-token"},
		}
		err := store.SetUserToken(context.Background(), userEmail, "test-service", token)
		require.NoError(t, err)

		form := url.Values{}
		form.Set("service", "test-service")

		req := httptest.NewRequest(http.MethodPost, "/oauth/disconnect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx := context.WithValue(req.Context(), oauth.GetUserContextKey(), userEmail)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handlers.DisconnectHandler(rec, req)

		assert.Equal(t, http.StatusSeeOther, rec.Code)

		_, err = store.GetUserToken(context.Background(), userEmail, "test-service")
		assert.Error(t, err)
	})

	t.Run("missing service parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/disconnect", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx := context.WithValue(req.Context(), oauth.GetUserContextKey(), "user@example.com")
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handlers.DisconnectHandler(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestGetUserFriendlyOAuthError(t *testing.T) {
	tests := []struct {
		errorCode   string
		description string
		contains    string
	}{
		{
			errorCode: "access_denied",
			contains:  "cancelled the authorization",
		},
		{
			errorCode:   "server_error",
			description: "Internal server error",
			contains:    "OAuth provider error: Internal server error",
		},
		{
			errorCode: "temporarily_unavailable",
			contains:  "temporarily unavailable",
		},
		{
			errorCode:   "unknown_error",
			description: "Something went wrong",
			contains:    "OAuth authorization failed: Something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			result := getUserFriendlyOAuthError(tt.errorCode, tt.description)
			assert.Contains(t, result, tt.contains)
		})
	}
}
