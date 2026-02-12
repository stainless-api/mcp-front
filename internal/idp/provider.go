package idp

import (
	"context"

	"golang.org/x/oauth2"
)

// Identity represents user identity as reported by an identity provider.
// Providers populate this with identity information only — access control
// (domain, org checks) is handled by the authorization layer.
type Identity struct {
	ProviderType  string   `json:"provider_type"`
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Domain        string   `json:"domain"`
	Organizations []string `json:"organizations,omitempty"`
}

// Provider abstracts identity provider operations.
type Provider interface {
	// Type returns the provider type identifier (e.g., "google", "azure", "github", "oidc").
	Type() string

	// AuthURL generates the authorization URL for the OAuth flow.
	AuthURL(state string) string

	// ExchangeCode exchanges an authorization code for tokens.
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)

	// UserInfo fetches user identity from the provider.
	// Returns identity information only — no access control validation.
	UserInfo(ctx context.Context, token *oauth2.Token) (*Identity, error)
}
