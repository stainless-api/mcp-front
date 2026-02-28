package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTokenMiddleware_GCPFallback(t *testing.T) {
	jwtSecret := []byte(strings.Repeat("a", 32))
	authServer, err := NewAuthorizationServer(AuthorizationServerConfig{
		JWTSecret:       jwtSecret,
		Issuer:          "https://test.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	})
	require.NoError(t, err)

	identity := idp.Identity{
		Email:        "user@example.com",
		ProviderType: "google",
		Subject:      "123",
	}

	token, err := authServer.issueTokenPair(identity, "client-1", []string{"openid"}, []string{"https://test.example.com/gateway"})
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, ok := GetUserFromContext(r.Context())
		if ok {
			w.Write([]byte(email))
		}
		w.WriteHeader(http.StatusOK)
	})

	t.Run("custom token works with nil GCP validator", func(t *testing.T) {
		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "user@example.com", rec.Body.String())
	})

	t.Run("invalid token rejected with nil GCP validator", func(t *testing.T) {
		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("missing authorization header rejected", func(t *testing.T) {
		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestValidateTokenMiddleware_GCPValidatorIntegration(t *testing.T) {
	t.Run("GCP validator creation requires network", func(t *testing.T) {
		ctx := context.Background()
		validator, err := NewGCPIDTokenValidator(ctx, "https://test.example.com")
		if err != nil {
			t.Skipf("GCP ID token validator creation failed (expected outside GCP): %v", err)
		}
		assert.NotNil(t, validator)
		assert.Equal(t, "https://test.example.com", validator.audience)
	})
}
