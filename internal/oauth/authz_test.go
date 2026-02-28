package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type testClient struct {
	id           string
	secret       []byte
	redirectURIs []string
	scopes       []string
	audience     []string
	public       bool
}

func (c *testClient) GetID() string             { return c.id }
func (c *testClient) GetSecret() []byte         { return c.secret }
func (c *testClient) GetRedirectURIs() []string { return c.redirectURIs }
func (c *testClient) GetScopes() []string       { return c.scopes }
func (c *testClient) GetAudience() []string     { return c.audience }
func (c *testClient) IsPublic() bool            { return c.public }

func newTestServer(t *testing.T) *AuthorizationServer {
	t.Helper()
	s, err := NewAuthorizationServer(AuthorizationServerConfig{
		JWTSecret:       []byte(strings.Repeat("s", 32)),
		Issuer:          "https://mcp.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	})
	require.NoError(t, err)
	return s
}

func newPublicClient() *testClient {
	return &testClient{
		id:           "test-client-id",
		redirectURIs: []string{"http://localhost:6274/callback"},
		scopes:       []string{"read", "write", "openid", "email", "profile", "offline_access"},
		audience:     []string{"https://mcp.example.com"},
		public:       true,
	}
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestAuthorizationServer_NewValidation(t *testing.T) {
	t.Run("rejects short JWT secret", func(t *testing.T) {
		_, err := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret: []byte("short"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})

	t.Run("accepts valid config", func(t *testing.T) {
		s, err := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret: []byte(strings.Repeat("a", 32)),
			Issuer:    "https://example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, s)
	})
}

func TestAuthorizationServer_ValidateAuthorizeRequest(t *testing.T) {
	s := newTestServer(t)
	client := newPublicClient()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	t.Run("valid request", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:6274/callback&code_challenge="+challenge+"&code_challenge_method=S256&scope=read+write&state=test-state&resource=https://mcp.example.com/postgres", nil)
		params, err := s.ValidateAuthorizeRequest(r, client)
		require.NoError(t, err)
		assert.Equal(t, "test-client-id", params.ClientID)
		assert.Equal(t, "http://localhost:6274/callback", params.RedirectURI)
		assert.Equal(t, "test-state", params.State)
		assert.Equal(t, []string{"read", "write"}, params.Scopes)
		assert.Equal(t, challenge, params.PKCEChallenge)
	})

	t.Run("unsupported response_type", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=token&client_id=test-client-id&redirect_uri=http://localhost:6274/callback", nil)
		_, err := s.ValidateAuthorizeRequest(r, client)
		require.Error(t, err)
		var oauthErr *OAuthError
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, ErrUnsupportedResponseType, oauthErr.Code)
	})

	t.Run("missing redirect_uri", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id", nil)
		_, err := s.ValidateAuthorizeRequest(r, client)
		require.Error(t, err)
	})

	t.Run("unregistered redirect_uri", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://evil.com/callback&code_challenge="+challenge+"&code_challenge_method=S256", nil)
		_, err := s.ValidateAuthorizeRequest(r, client)
		require.Error(t, err)
	})

	t.Run("missing PKCE for public client", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:6274/callback&state=x", nil)
		_, err := s.ValidateAuthorizeRequest(r, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PKCE")
	})

	t.Run("unsupported PKCE method", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:6274/callback&code_challenge=abc&code_challenge_method=plain&state=x", nil)
		_, err := s.ValidateAuthorizeRequest(r, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "S256")
	})

	t.Run("missing resource parameter", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:6274/callback&code_challenge="+challenge+"&code_challenge_method=S256&state=x", nil)
		_, err := s.ValidateAuthorizeRequest(r, client)
		require.Error(t, err)
		var oauthErr *OAuthError
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, ErrInvalidRequest, oauthErr.Code)
		assert.Contains(t, oauthErr.Description, "resource")
	})

	t.Run("with resource parameters", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:6274/callback&code_challenge="+challenge+"&code_challenge_method=S256&state=x&resource=https://mcp.example.com/postgres", nil)
		params, err := s.ValidateAuthorizeRequest(r, client)
		require.NoError(t, err)
		assert.Equal(t, []string{"https://mcp.example.com/postgres"}, params.Audience)
	})
}

func TestAuthorizationServer_FullFlow(t *testing.T) {
	s := newTestServer(t)
	client := newPublicClient()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:6274/callback&code_challenge="+challenge+"&code_challenge_method=S256&scope=read+write&state=test-state&resource=https://mcp.example.com/postgres", nil)

	params, err := s.ValidateAuthorizeRequest(r, client)
	require.NoError(t, err)

	identity := idp.Identity{
		ProviderType:  "google",
		Subject:       "123",
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Domain:        "example.com",
	}

	grant, err := s.IssueCode(params, identity)
	require.NoError(t, err)
	assert.NotEmpty(t, grant.Code)
	assert.Equal(t, "test-client-id", grant.ClientID)
	assert.Equal(t, identity, grant.Identity)
	assert.Equal(t, []string{"https://mcp.example.com/postgres"}, grant.Audience)

	pair, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
		RedirectURI:  "http://localhost:6274/callback",
		CodeVerifier: verifier,
	}, client)
	require.NoError(t, err)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.Equal(t, "Bearer", pair.TokenType)
	assert.Equal(t, 3600, pair.ExpiresIn)
	assert.Equal(t, "read write", pair.Scope)

	claims, err := s.ValidateAccessToken(pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Identity.Email)
	assert.Equal(t, "test-client-id", claims.ClientID)
	assert.Equal(t, []string{"https://mcp.example.com/postgres"}, claims.Audience)
	assert.Equal(t, []string{"read", "write"}, claims.Scopes)

	refreshPair, err := s.RefreshTokens(pair.RefreshToken, client, &RefreshRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, refreshPair.AccessToken)
	assert.NotEqual(t, pair.AccessToken, refreshPair.AccessToken)
}

func TestAuthorizationServer_ExchangeCode_Errors(t *testing.T) {
	s := newTestServer(t)
	client := newPublicClient()
	verifier := "test-verifier-string"

	identity := idp.Identity{Email: "user@example.com"}
	params := &AuthorizeParams{
		ClientID:      "test-client-id",
		RedirectURI:   "http://localhost:6274/callback",
		State:         "s",
		Scopes:        []string{"read"},
		PKCEChallenge: pkceChallenge(verifier),
	}

	t.Run("expired code", func(t *testing.T) {
		grant, _ := s.IssueCode(params, identity)
		grant.ExpiresAt = time.Now().Add(-1 * time.Minute)
		_, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
			RedirectURI:  "http://localhost:6274/callback",
			CodeVerifier: verifier,
		}, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("wrong client", func(t *testing.T) {
		grant, _ := s.IssueCode(params, identity)
		wrongClient := &testClient{id: "other-client", redirectURIs: []string{"http://localhost:6274/callback"}, public: true}
		_, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
			RedirectURI:  "http://localhost:6274/callback",
			CodeVerifier: verifier,
		}, wrongClient)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_id mismatch")
	})

	t.Run("wrong redirect_uri", func(t *testing.T) {
		grant, _ := s.IssueCode(params, identity)
		_, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
			RedirectURI:  "http://evil.com/callback",
			CodeVerifier: verifier,
		}, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redirect_uri mismatch")
	})

	t.Run("wrong PKCE verifier", func(t *testing.T) {
		grant, _ := s.IssueCode(params, identity)
		_, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
			RedirectURI:  "http://localhost:6274/callback",
			CodeVerifier: "wrong-verifier",
		}, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PKCE")
	})

	t.Run("missing PKCE verifier", func(t *testing.T) {
		grant, _ := s.IssueCode(params, identity)
		_, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
			RedirectURI: "http://localhost:6274/callback",
		}, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "code_verifier is required")
	})
}

func TestAuthorizationServer_ConfidentialClient(t *testing.T) {
	s := newTestServer(t)
	secret := "test-client-secret"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	client := &testClient{
		id:           "conf-client",
		secret:       hashed,
		redirectURIs: []string{"http://localhost:6274/callback"},
		scopes:       []string{"read"},
		audience:     []string{"https://mcp.example.com"},
		public:       false,
	}

	identity := idp.Identity{Email: "user@example.com"}
	params := &AuthorizeParams{
		ClientID:    "conf-client",
		RedirectURI: "http://localhost:6274/callback",
		Scopes:      []string{"read"},
	}

	grant, err := s.IssueCode(params, identity)
	require.NoError(t, err)

	t.Run("valid secret", func(t *testing.T) {
		pair, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
			RedirectURI:  "http://localhost:6274/callback",
			ClientSecret: secret,
		}, client)
		require.NoError(t, err)
		assert.NotEmpty(t, pair.AccessToken)
	})

	t.Run("wrong secret", func(t *testing.T) {
		grant2, _ := s.IssueCode(params, identity)
		_, err := s.ExchangeCode(grant2, &ExchangeCodeRequest{
			RedirectURI:  "http://localhost:6274/callback",
			ClientSecret: "wrong-secret",
		}, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
	})
}

func TestAuthorizationServer_RefreshTokens_Errors(t *testing.T) {
	s := newTestServer(t)
	client := newPublicClient()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	identity := idp.Identity{Email: "user@example.com"}
	params := &AuthorizeParams{
		ClientID:      "test-client-id",
		RedirectURI:   "http://localhost:6274/callback",
		State:         "s",
		Scopes:        []string{"read"},
		PKCEChallenge: pkceChallenge(verifier),
	}

	grant, err := s.IssueCode(params, identity)
	require.NoError(t, err)

	pair, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
		RedirectURI:  "http://localhost:6274/callback",
		CodeVerifier: verifier,
	}, client)
	require.NoError(t, err)

	t.Run("invalid refresh token", func(t *testing.T) {
		_, err := s.RefreshTokens("garbage-token", client, &RefreshRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})

	t.Run("wrong client", func(t *testing.T) {
		wrongClient := &testClient{id: "other-client", public: true}
		_, err := s.RefreshTokens(pair.RefreshToken, wrongClient, &RefreshRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "different client")
	})

	t.Run("token from different server", func(t *testing.T) {
		otherServer, _ := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret: []byte(strings.Repeat("x", 32)),
			Issuer:    "https://other.example.com",
		})
		_, err := otherServer.RefreshTokens(pair.RefreshToken, client, &RefreshRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})
}

func TestAuthorizationServer_ConfidentialClientRefresh(t *testing.T) {
	s := newTestServer(t)
	secret := "test-client-secret"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	client := &testClient{
		id:           "conf-client",
		secret:       hashed,
		redirectURIs: []string{"http://localhost:6274/callback"},
		scopes:       []string{"read"},
		audience:     []string{"https://mcp.example.com"},
		public:       false,
	}

	identity := idp.Identity{Email: "user@example.com"}
	params := &AuthorizeParams{
		ClientID:    "conf-client",
		RedirectURI: "http://localhost:6274/callback",
		Scopes:      []string{"read"},
	}

	grant, err := s.IssueCode(params, identity)
	require.NoError(t, err)

	pair, err := s.ExchangeCode(grant, &ExchangeCodeRequest{
		RedirectURI:  "http://localhost:6274/callback",
		ClientSecret: secret,
	}, client)
	require.NoError(t, err)

	t.Run("valid secret", func(t *testing.T) {
		refreshed, err := s.RefreshTokens(pair.RefreshToken, client, &RefreshRequest{ClientSecret: secret})
		require.NoError(t, err)
		assert.NotEmpty(t, refreshed.AccessToken)
		assert.NotEqual(t, pair.AccessToken, refreshed.AccessToken)
	})

	t.Run("wrong secret", func(t *testing.T) {
		_, err := s.RefreshTokens(pair.RefreshToken, client, &RefreshRequest{ClientSecret: "wrong"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
	})

	t.Run("missing secret", func(t *testing.T) {
		_, err := s.RefreshTokens(pair.RefreshToken, client, &RefreshRequest{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
	})
}

func TestAuthorizationServer_ValidateAccessToken_Errors(t *testing.T) {
	s := newTestServer(t)

	t.Run("garbage token", func(t *testing.T) {
		_, err := s.ValidateAccessToken("not-a-token")
		require.Error(t, err)
	})

	t.Run("token from different server", func(t *testing.T) {
		other, _ := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret: []byte(strings.Repeat("x", 32)),
			Issuer:    "https://other.example.com",
		})
		client := newPublicClient()
		verifier := "test-verifier-string-with-enough-length"
		params := &AuthorizeParams{
			ClientID:      client.id,
			RedirectURI:   client.redirectURIs[0],
			Scopes:        []string{"read"},
			PKCEChallenge: pkceChallenge(verifier),
		}
		grant, _ := other.IssueCode(params, idp.Identity{Email: "u@example.com"})
		pair, _ := other.ExchangeCode(grant, &ExchangeCodeRequest{
			RedirectURI:  client.redirectURIs[0],
			CodeVerifier: verifier,
		}, client)

		_, err := s.ValidateAccessToken(pair.AccessToken)
		require.Error(t, err)
	})
}

func TestAuthorizationServer_RefreshTokenScopes(t *testing.T) {
	t.Run("empty scopes list means always issue", func(t *testing.T) {
		s, _ := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret:          []byte(strings.Repeat("a", 32)),
			Issuer:             "https://example.com",
			RefreshTokenScopes: []string{},
		})
		assert.True(t, s.shouldIssueRefreshToken([]string{"read"}))
	})

	t.Run("nil scopes list means always issue", func(t *testing.T) {
		s, _ := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret: []byte(strings.Repeat("a", 32)),
			Issuer:    "https://example.com",
		})
		assert.True(t, s.shouldIssueRefreshToken([]string{"read"}))
	})

	t.Run("required scope present", func(t *testing.T) {
		s, _ := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret:          []byte(strings.Repeat("a", 32)),
			Issuer:             "https://example.com",
			RefreshTokenScopes: []string{"offline_access"},
		})
		assert.True(t, s.shouldIssueRefreshToken([]string{"read", "offline_access"}))
	})

	t.Run("required scope missing", func(t *testing.T) {
		s, _ := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret:          []byte(strings.Repeat("a", 32)),
			Issuer:             "https://example.com",
			RefreshTokenScopes: []string{"offline_access"},
		})
		assert.False(t, s.shouldIssueRefreshToken([]string{"read"}))
	})
}

func TestWriteTokenResponse(t *testing.T) {
	w := httptest.NewRecorder()
	WriteTokenResponse(w, &TokenPair{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "test-token")
}

func TestAuthorizationServer_MinStateEntropy(t *testing.T) {
	s, _ := NewAuthorizationServer(AuthorizationServerConfig{
		JWTSecret:       []byte(strings.Repeat("a", 32)),
		Issuer:          "https://example.com",
		MinStateEntropy: 8,
	})

	client := newPublicClient()
	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	t.Run("rejects short state", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:6274/callback&code_challenge="+challenge+"&code_challenge_method=S256&state=short", nil)
		_, err := s.ValidateAuthorizeRequest(r, client)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state parameter must be at least")
	})

	t.Run("accepts long enough state", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/authorize?response_type=code&client_id=test-client-id&redirect_uri=http://localhost:6274/callback&code_challenge="+challenge+"&code_challenge_method=S256&state=long-enough-state-value&resource=https://example.com/svc", nil)
		params, err := s.ValidateAuthorizeRequest(r, client)
		require.NoError(t, err)
		assert.Equal(t, "long-enough-state-value", params.State)
	})
}
