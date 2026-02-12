package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/browserauth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// mockIDPProvider is a mock IDP provider for testing
type mockIDPProvider struct{}

func (m *mockIDPProvider) Type() string {
	return "mock"
}

func (m *mockIDPProvider) AuthURL(state string) string {
	return "https://auth.example.com/authorize?state=" + state
}

func (m *mockIDPProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "test-token"}, nil
}

func (m *mockIDPProvider) UserInfo(ctx context.Context, token *oauth2.Token) (*idp.Identity, error) {
	return &idp.Identity{
		ProviderType:  "mock",
		Subject:       "123",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Domain:        "example.com",
	}, nil
}

func TestAuthenticationBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectAuth  bool
		description string
	}{
		{
			name:        "oauth_endpoints_are_public",
			path:        "/.well-known/oauth-authorization-server",
			expectAuth:  false,
			description: "OAuth discovery must be public",
		},
		{
			name:        "health_is_public",
			path:        "/health",
			expectAuth:  false,
			description: "Health check must be public",
		},
		{
			name:        "token_management_requires_auth",
			path:        "/my/tokens",
			expectAuth:  true,
			description: "Token management requires auth",
		},
	}

	// Setup test OAuth configuration
	oauthConfig := config.OAuthAuthConfig{
		Kind:   config.AuthKindOAuth,
		Issuer: "https://test.example.com",
		IDP: config.IDPConfig{
			Provider:     "google",
			ClientID:     "test-client-id",
			ClientSecret: config.Secret("test-client-secret"),
			RedirectURI:  "https://test.example.com/oauth/callback",
		},
		JWTSecret:       config.Secret(strings.Repeat("a", 32)),
		EncryptionKey:   config.Secret(strings.Repeat("b", 32)),
		TokenTTL:        time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		Storage:         "memory",
		AllowedDomains:  []string{"example.com"},
		AllowedOrigins:  []string{"https://test.example.com"},
	}

	// Create storage
	store := storage.NewMemoryStorage()

	// Create OAuth provider
	jwtSecret, err := oauth.GenerateJWTSecret(string(oauthConfig.JWTSecret))
	require.NoError(t, err)
	oauthProvider, err := oauth.NewOAuthProvider(oauthConfig, store, jwtSecret)
	require.NoError(t, err)

	// Create session encryptor
	sessionEncryptor, err := oauth.NewSessionEncryptor([]byte(oauthConfig.EncryptionKey))
	require.NoError(t, err)

	// Create service OAuth client
	serviceOAuthClient := auth.NewServiceOAuthClient(store, "https://test.example.com", []byte(strings.Repeat("k", 32)))

	// Create mock IDP provider for testing
	mockIDP := &mockIDPProvider{}

	// Create handlers
	authHandlers := NewAuthHandlers(
		oauthProvider,
		oauthConfig,
		mockIDP,
		store,
		sessionEncryptor,
		map[string]*config.MCPClientConfig{},
		serviceOAuthClient,
	)

	tokenHandlers := NewTokenHandlers(store, map[string]*config.MCPClientConfig{}, true, serviceOAuthClient)

	// Build mux with middlewares
	mux := http.NewServeMux()
	corsMiddleware := NewCORSMiddleware(oauthConfig.AllowedOrigins)
	browserStateToken := crypto.NewTokenSigner([]byte(oauthConfig.EncryptionKey), 10*time.Minute)

	// Public OAuth endpoints
	mux.Handle("/.well-known/oauth-authorization-server", ChainMiddleware(
		http.HandlerFunc(authHandlers.WellKnownHandler),
		corsMiddleware,
	))

	// Protected endpoints
	tokenMiddleware := []MiddlewareFunc{
		corsMiddleware,
		NewBrowserSSOMiddleware(oauthConfig, mockIDP, sessionEncryptor, &browserStateToken),
	}

	mux.Handle("/my/tokens", ChainMiddleware(
		http.HandlerFunc(tokenHandlers.ListTokensHandler),
		tokenMiddleware...,
	))

	mux.Handle("/oauth/services", ChainMiddleware(
		http.HandlerFunc(authHandlers.ServiceSelectionHandler),
		tokenMiddleware...,
	))

	// Health endpoint (no auth)
	mux.Handle("/health", NewHealthHandler())

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test without session cookie
			req, err := http.NewRequest("GET", srv.URL+tt.path, nil)
			require.NoError(t, err)

			// Use a client that doesn't follow redirects
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			if tt.expectAuth {
				// Browser SSO redirects to OAuth when no session cookie
				assert.Equal(t, http.StatusFound, resp.StatusCode, tt.description+" - should redirect to OAuth")
				location := resp.Header.Get("Location")
				assert.Contains(t, location, "auth", tt.description+" - should redirect to Google OAuth")
			} else {
				// Should not be blocked by auth
				assert.NotEqual(t, http.StatusUnauthorized, resp.StatusCode, tt.description+" - should not require auth")
				assert.NotEqual(t, http.StatusForbidden, resp.StatusCode, tt.description+" - should not require auth")
				assert.NotEqual(t, http.StatusFound, resp.StatusCode, tt.description+" - should not redirect for auth")
			}

			// Test with valid session cookie (if auth is expected)
			if tt.expectAuth {
				// Create session data
				sessionData := browserauth.SessionCookie{
					Email:    "test@example.com",
					Provider: "mock",
					Expires:  time.Now().Add(24 * time.Hour),
				}
				jsonData, err := json.Marshal(sessionData)
				require.NoError(t, err)

				// Encrypt the session data
				encrypted, err := sessionEncryptor.Encrypt(string(jsonData))
				require.NoError(t, err)

				// Test with valid session cookie
				req2, err := http.NewRequest("GET", srv.URL+tt.path, nil)
				require.NoError(t, err)
				req2.AddCookie(&http.Cookie{
					Name:  "mcp_session",
					Value: encrypted,
				})

				resp2, err := client.Do(req2)
				require.NoError(t, err)
				defer resp2.Body.Close()

				// Should allow access with valid session
				assert.Equal(t, http.StatusOK, resp2.StatusCode, tt.description+" - should allow with valid session")
			}
		})
	}
}

func TestOAuthEndpointHandlers(t *testing.T) {
	oauthConfig := config.OAuthAuthConfig{
		Kind:   config.AuthKindOAuth,
		Issuer: "https://test.example.com",
		IDP: config.IDPConfig{
			Provider:     "google",
			ClientID:     "test-client-id",
			ClientSecret: config.Secret("test-client-secret"),
			RedirectURI:  "https://test.example.com/oauth/callback",
		},
		JWTSecret:       config.Secret(strings.Repeat("a", 32)),
		EncryptionKey:   config.Secret(strings.Repeat("b", 32)),
		TokenTTL:        time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		Storage:         "memory",
		AllowedDomains:  []string{"example.com"},
		AllowedOrigins:  []string{"https://test.example.com"},
	}

	store := storage.NewMemoryStorage()
	jwtSecret, err := oauth.GenerateJWTSecret(string(oauthConfig.JWTSecret))
	require.NoError(t, err)
	oauthProvider, err := oauth.NewOAuthProvider(oauthConfig, store, jwtSecret)
	require.NoError(t, err)
	sessionEncryptor, err := oauth.NewSessionEncryptor([]byte(oauthConfig.EncryptionKey))
	require.NoError(t, err)
	serviceOAuthClient := auth.NewServiceOAuthClient(store, "https://test.example.com", []byte(strings.Repeat("k", 32)))
	mockIDP := &mockIDPProvider{}

	authHandlers := NewAuthHandlers(
		oauthProvider,
		oauthConfig,
		mockIDP,
		store,
		sessionEncryptor,
		map[string]*config.MCPClientConfig{},
		serviceOAuthClient,
	)

	t.Run("WellKnownHandler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		rec := httptest.NewRecorder()

		authHandlers.WellKnownHandler(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

		var metadata map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &metadata)
		require.NoError(t, err)

		// Verify required OAuth metadata fields
		assert.Equal(t, "https://test.example.com", metadata["issuer"])
		assert.Equal(t, "https://test.example.com/authorize", metadata["authorization_endpoint"])
		assert.Equal(t, "https://test.example.com/token", metadata["token_endpoint"])
		assert.Equal(t, "https://test.example.com/register", metadata["registration_endpoint"])

		// Verify supported methods
		codeChallenges, ok := metadata["code_challenge_methods_supported"].([]any)
		require.True(t, ok)
		assert.Contains(t, codeChallenges, "S256")
	})

	t.Run("RegisterHandler creates public client", func(t *testing.T) {
		reqBody := `{
			"redirect_uris": ["https://client.example.com/callback"],
			"scope": "read write"
		}`

		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		authHandlers.RegisterHandler(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotEmpty(t, response["client_id"])
		assert.Empty(t, response["client_secret"], "Public client should not have secret")
		assert.Equal(t, "none", response["token_endpoint_auth_method"])
	})

	t.Run("ServiceSelectionHandler requires valid state", func(t *testing.T) {
		// Test requires valid browser session AND valid signed state
		// First test: No state parameter
		req := httptest.NewRequest(http.MethodGet, "/oauth/services", nil)

		// Add valid session cookie
		sessionData := browserauth.SessionCookie{
			Email:   "test@example.com",
			Expires: time.Now().Add(24 * time.Hour),
		}
		jsonData, err := json.Marshal(sessionData)
		require.NoError(t, err)
		encrypted, err := sessionEncryptor.Encrypt(string(jsonData))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{
			Name:  "mcp_session",
			Value: encrypted,
		})

		rec := httptest.NewRecorder()
		authHandlers.ServiceSelectionHandler(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code, "Should reject request without state")
		assert.Contains(t, rec.Body.String(), "Missing state parameter")
	})

	t.Run("RegisterHandler creates confidential client", func(t *testing.T) {
		reqBody := `{
			"redirect_uris": ["https://client.example.com/callback"],
			"scope": "read write",
			"token_endpoint_auth_method": "client_secret_post"
		}`

		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		authHandlers.RegisterHandler(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)

		var response map[string]any
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotEmpty(t, response["client_id"])
		assert.NotEmpty(t, response["client_secret"], "Confidential client should have secret")
		assert.Equal(t, "client_secret_post", response["token_endpoint_auth_method"])
	})
}

func TestBearerTokenAuth(t *testing.T) {
	// Unit test for bearer token authentication middleware
	serviceAuths := []config.ServiceAuth{
		{
			Type:   config.ServiceAuthTypeBearer,
			Tokens: []string{"valid-token-1", "valid-token-2"},
		},
	}

	tests := []struct {
		name         string
		authHeader   string
		expectStatus int
	}{
		{
			name:         "valid token 1",
			authHeader:   "Bearer valid-token-1",
			expectStatus: http.StatusOK,
		},
		{
			name:         "valid token 2",
			authHeader:   "Bearer valid-token-2",
			expectStatus: http.StatusOK,
		},
		{
			name:         "invalid token",
			authHeader:   "Bearer invalid-token",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "no auth header",
			authHeader:   "",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "malformed header",
			authHeader:   "InvalidFormat",
			expectStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			authHandler := NewServiceAuthMiddleware(serviceAuths)(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			authHandler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectStatus, rec.Code)
		})
	}
}

func TestValidateAccess(t *testing.T) {
	tests := []struct {
		name           string
		allowedDomains []string
		allowedOrgs    []string
		identity       *idp.Identity
		wantErr        bool
		errContains    string
	}{
		{
			name:           "no_restrictions",
			allowedDomains: nil,
			allowedOrgs:    nil,
			identity:       &idp.Identity{Domain: "any.com", Organizations: []string{"any-org"}},
			wantErr:        false,
		},
		{
			name:           "domain_allowed",
			allowedDomains: []string{"company.com"},
			identity:       &idp.Identity{Domain: "company.com"},
			wantErr:        false,
		},
		{
			name:           "domain_rejected",
			allowedDomains: []string{"company.com"},
			identity:       &idp.Identity{Domain: "other.com"},
			wantErr:        true,
			errContains:    "domain 'other.com' is not allowed",
		},
		{
			name:        "org_allowed",
			allowedOrgs: []string{"allowed-org"},
			identity:    &idp.Identity{Domain: "any.com", Organizations: []string{"allowed-org", "other-org"}},
			wantErr:     false,
		},
		{
			name:        "org_rejected",
			allowedOrgs: []string{"required-org"},
			identity:    &idp.Identity{Domain: "any.com", Organizations: []string{"other-org"}},
			wantErr:     true,
			errContains: "not a member of any allowed organization",
		},
		{
			name:           "domain_and_org_both_pass",
			allowedDomains: []string{"company.com"},
			allowedOrgs:    []string{"my-org"},
			identity:       &idp.Identity{Domain: "company.com", Organizations: []string{"my-org"}},
			wantErr:        false,
		},
		{
			name:           "domain_fails_before_org_check",
			allowedDomains: []string{"company.com"},
			allowedOrgs:    []string{"my-org"},
			identity:       &idp.Identity{Domain: "other.com", Organizations: []string{"my-org"}},
			wantErr:        true,
			errContains:    "domain 'other.com' is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &AuthHandlers{
				authConfig: config.OAuthAuthConfig{
					AllowedDomains: tt.allowedDomains,
					IDP: config.IDPConfig{
						AllowedOrgs: tt.allowedOrgs,
					},
				},
			}

			err := h.validateAccess(tt.identity)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}
