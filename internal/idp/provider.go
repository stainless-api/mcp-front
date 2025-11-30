package idp

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/oauth2"
)

// UserInfo represents user information from any identity provider.
// ProviderType is included for multi-IDP readiness.
type UserInfo struct {
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

	// UserInfo fetches user information and validates access.
	// allowedDomains is used for domain-based access control.
	// Provider-specific access control (e.g., GitHub org membership) is configured at construction.
	UserInfo(ctx context.Context, token *oauth2.Token, allowedDomains []string) (*UserInfo, error)
}

// ValidateDomain checks if the domain is in the allowed list.
// Returns nil if allowedDomains is empty (no restriction) or domain is allowed.
func ValidateDomain(domain string, allowedDomains []string) error {
	if len(allowedDomains) == 0 {
		return nil
	}
	if !slices.Contains(allowedDomains, domain) {
		return fmt.Errorf("domain '%s' is not allowed. Contact your administrator", domain)
	}
	return nil
}

// ParseClientRequest parses MCP client registration metadata.
// This is provider-agnostic as it deals with MCP client registration, not IDP.
func ParseClientRequest(metadata map[string]any) (redirectURIs []string, scopes []string, err error) {
	// Extract redirect URIs
	redirectURIs = []string{}
	if uris, ok := metadata["redirect_uris"].([]any); ok {
		for _, uri := range uris {
			if uriStr, ok := uri.(string); ok {
				redirectURIs = append(redirectURIs, uriStr)
			}
		}
	}

	if len(redirectURIs) == 0 {
		return nil, nil, fmt.Errorf("no valid redirect URIs provided")
	}

	// Extract scopes, default to read/write if not provided
	scopes = []string{"read", "write"} // Default MCP scopes
	if clientScopes, ok := metadata["scope"].(string); ok {
		if strings.TrimSpace(clientScopes) != "" {
			scopes = strings.Fields(clientScopes)
		}
	}

	return redirectURIs, scopes, nil
}
