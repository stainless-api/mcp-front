package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestNewOIDCProvider_WithDirectEndpoints(t *testing.T) {
	provider, err := NewOIDCProvider(OIDCConfig{
		ProviderType:     "custom",
		AuthorizationURL: "https://idp.example.com/authorize",
		TokenURL:         "https://idp.example.com/token",
		UserInfoURL:      "https://idp.example.com/userinfo",
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURI:      "https://example.com/callback",
	})

	require.NoError(t, err)
	require.NotNil(t, provider)
	assert.Equal(t, "custom", provider.Type())
}

func TestNewOIDCProvider_WithDiscovery(t *testing.T) {
	discovery := oidcDiscoveryDocument{
		Issuer:                "https://idp.example.com",
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		UserInfoEndpoint:      "https://idp.example.com/userinfo",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(discovery)
		require.NoError(t, err)
	}))
	defer server.Close()

	provider, err := NewOIDCProvider(OIDCConfig{
		DiscoveryURL: server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://example.com/callback",
	})

	require.NoError(t, err)
	require.NotNil(t, provider)
	assert.Equal(t, "oidc", provider.Type())
}

func TestNewOIDCProvider_MissingEndpoints(t *testing.T) {
	_, err := NewOIDCProvider(OIDCConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://example.com/callback",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "discoveryUrl or all endpoints")
}

func TestNewOIDCProvider_PartialEndpoints(t *testing.T) {
	_, err := NewOIDCProvider(OIDCConfig{
		AuthorizationURL: "https://idp.example.com/authorize",
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURI:      "https://example.com/callback",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "discoveryUrl or all endpoints")
}

func TestNewOIDCProvider_DiscoveryMissingEndpoints(t *testing.T) {
	discovery := oidcDiscoveryDocument{
		Issuer: "https://idp.example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(discovery)
		require.NoError(t, err)
	}))
	defer server.Close()

	_, err := NewOIDCProvider(OIDCConfig{
		DiscoveryURL: server.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://example.com/callback",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required endpoints")
}

func TestOIDCProvider_AuthURL(t *testing.T) {
	provider, err := NewOIDCProvider(OIDCConfig{
		AuthorizationURL: "https://idp.example.com/authorize",
		TokenURL:         "https://idp.example.com/token",
		UserInfoURL:      "https://idp.example.com/userinfo",
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURI:      "https://example.com/callback",
	})
	require.NoError(t, err)

	authURL := provider.AuthURL("test-state")

	assert.Contains(t, authURL, "https://idp.example.com/authorize")
	assert.Contains(t, authURL, "state=test-state")
	assert.Contains(t, authURL, "client_id=client-id")
}

func TestOIDCProvider_UserInfo(t *testing.T) {
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := oidcUserInfoResponse{
			Sub:           "12345",
			Email:         "user@example.com",
			EmailVerified: true,
			Name:          "Test User",
			Picture:       "https://example.com/photo.jpg",
		}
		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer userInfoServer.Close()

	provider, err := NewOIDCProvider(OIDCConfig{
		AuthorizationURL: "https://idp.example.com/authorize",
		TokenURL:         "https://idp.example.com/token",
		UserInfoURL:      userInfoServer.URL,
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURI:      "https://example.com/callback",
	})
	require.NoError(t, err)

	token := &oauth2.Token{AccessToken: "test-token"}
	identity, err := provider.UserInfo(context.Background(), token)

	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "oidc", identity.ProviderType)
	assert.Equal(t, "12345", identity.Subject)
	assert.Equal(t, "user@example.com", identity.Email)
	assert.Equal(t, "example.com", identity.Domain)
	assert.True(t, identity.EmailVerified)
}

func TestOIDCProvider_DefaultScopes(t *testing.T) {
	provider, err := NewOIDCProvider(OIDCConfig{
		AuthorizationURL: "https://idp.example.com/authorize",
		TokenURL:         "https://idp.example.com/token",
		UserInfoURL:      "https://idp.example.com/userinfo",
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURI:      "https://example.com/callback",
	})
	require.NoError(t, err)

	authURL := provider.AuthURL("test-state")
	assert.Contains(t, authURL, "scope=openid")
}

func TestOIDCProvider_CustomScopes(t *testing.T) {
	provider, err := NewOIDCProvider(OIDCConfig{
		AuthorizationURL: "https://idp.example.com/authorize",
		TokenURL:         "https://idp.example.com/token",
		UserInfoURL:      "https://idp.example.com/userinfo",
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
		RedirectURI:      "https://example.com/callback",
		Scopes:           []string{"openid", "custom_scope"},
	})
	require.NoError(t, err)

	authURL := provider.AuthURL("test-state")
	assert.Contains(t, authURL, "scope=openid")
	assert.Contains(t, authURL, "custom_scope")
}
