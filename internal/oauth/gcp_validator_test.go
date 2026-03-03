package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockTokenInfoServer(email string, expiresIn int, emailVerified bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("access_token")
		if token == "" || token == "invalid-token" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
			return
		}
		verified := "false"
		if emailVerified {
			verified = "true"
		}
		json.NewEncoder(w).Encode(map[string]string{
			"email":          email,
			"email_verified": verified,
			"expires_in":     fmt.Sprintf("%d", expiresIn),
		})
	}))
}

func TestGCPAccessTokenValidator(t *testing.T) {
	t.Run("valid token returns email", func(t *testing.T) {
		srv := newMockTokenInfoServer("sa@project.iam.gserviceaccount.com", 3600, true)
		defer srv.Close()

		v := &GCPAccessTokenValidator{
			tokenInfoURL: srv.URL,
			httpClient:   srv.Client(),
		}

		email, err := v.Validate(t.Context(), "valid-token")
		require.NoError(t, err)
		assert.Equal(t, "sa@project.iam.gserviceaccount.com", email)
	})

	t.Run("invalid token returns error", func(t *testing.T) {
		srv := newMockTokenInfoServer("", 0, false)
		defer srv.Close()

		v := &GCPAccessTokenValidator{
			tokenInfoURL: srv.URL,
			httpClient:   srv.Client(),
		}

		_, err := v.Validate(t.Context(), "invalid-token")
		assert.Error(t, err)
	})

	t.Run("unverified email returns error", func(t *testing.T) {
		srv := newMockTokenInfoServer("sa@example.com", 3600, false)
		defer srv.Close()

		v := &GCPAccessTokenValidator{
			tokenInfoURL: srv.URL,
			httpClient:   srv.Client(),
		}

		_, err := v.Validate(t.Context(), "valid-token")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "email not verified")
	})

	t.Run("caches valid responses", func(t *testing.T) {
		callCount := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			json.NewEncoder(w).Encode(map[string]string{
				"email":          "sa@project.iam.gserviceaccount.com",
				"email_verified": "true",
				"expires_in":     "3600",
			})
		}))
		defer srv.Close()

		v := &GCPAccessTokenValidator{
			tokenInfoURL: srv.URL,
			httpClient:   srv.Client(),
		}

		email1, err := v.Validate(t.Context(), "cached-token")
		require.NoError(t, err)

		email2, err := v.Validate(t.Context(), "cached-token")
		require.NoError(t, err)

		assert.Equal(t, email1, email2)
		assert.Equal(t, 1, callCount)
	})
}

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
		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, nil, nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "user@example.com", rec.Body.String())
	})

	t.Run("invalid token rejected with nil GCP validator", func(t *testing.T) {
		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, nil, nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("missing authorization header rejected", func(t *testing.T) {
		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, nil, nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("JWT auth ignores X-On-Behalf-Of header", func(t *testing.T) {
		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, nil, nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		req.Header.Set("X-On-Behalf-Of", "impersonated@example.com")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "user@example.com", rec.Body.String())
	})

	t.Run("GCP access token auth with impersonation", func(t *testing.T) {
		srv := newMockTokenInfoServer("sa@project.iam.gserviceaccount.com", 3600, true)
		defer srv.Close()

		gcpValidator := &GCPAccessTokenValidator{
			tokenInfoURL: srv.URL,
			httpClient:   srv.Client(),
		}

		authHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			email, _ := GetUserFromContext(r.Context())
			authToken, _ := GetAuthTokenFromContext(r.Context())
			w.Write([]byte(email + "|" + authToken))
		})

		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, gcpValidator, []string{"vori.com"})
		wrapped := middleware(authHandler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		req.Header.Set("Authorization", "Bearer gcp-access-token")
		req.Header.Set("X-On-Behalf-Of", "user@vori.com")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "user@vori.com|gcp-access-token", rec.Body.String())
	})

	t.Run("GCP access token impersonation rejected for disallowed domain", func(t *testing.T) {
		srv := newMockTokenInfoServer("sa@project.iam.gserviceaccount.com", 3600, true)
		defer srv.Close()

		gcpValidator := &GCPAccessTokenValidator{
			tokenInfoURL: srv.URL,
			httpClient:   srv.Client(),
		}

		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, gcpValidator, []string{"vori.com"})
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		req.Header.Set("Authorization", "Bearer gcp-access-token")
		req.Header.Set("X-On-Behalf-Of", "attacker@evil.com")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("GCP access token without impersonation uses service account email", func(t *testing.T) {
		srv := newMockTokenInfoServer("sa@project.iam.gserviceaccount.com", 3600, true)
		defer srv.Close()

		gcpValidator := &GCPAccessTokenValidator{
			tokenInfoURL: srv.URL,
			httpClient:   srv.Client(),
		}

		middleware := NewValidateTokenMiddleware(authServer, "https://test.example.com", true, gcpValidator, nil)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/gateway/sse", nil)
		req.Header.Set("Authorization", "Bearer gcp-access-token")
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "sa@project.iam.gserviceaccount.com", rec.Body.String())
	})
}
