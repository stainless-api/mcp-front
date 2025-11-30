package idp

import (
	"fmt"

	"github.com/dgellow/mcp-front/internal/config"
)

// NewProvider creates a Provider based on the IDPConfig.
func NewProvider(cfg config.IDPConfig) (Provider, error) {
	switch cfg.Provider {
	case "google":
		return NewGoogleProvider(
			cfg.ClientID,
			string(cfg.ClientSecret),
			cfg.RedirectURI,
		), nil

	case "azure":
		return NewAzureProvider(
			cfg.TenantID,
			cfg.ClientID,
			string(cfg.ClientSecret),
			cfg.RedirectURI,
		)

	case "github":
		return NewGitHubProvider(
			cfg.ClientID,
			string(cfg.ClientSecret),
			cfg.RedirectURI,
			cfg.AllowedOrgs,
		), nil

	case "oidc":
		return NewOIDCProvider(OIDCConfig{
			ProviderType:     "oidc",
			DiscoveryURL:     cfg.DiscoveryURL,
			AuthorizationURL: cfg.AuthorizationURL,
			TokenURL:         cfg.TokenURL,
			UserInfoURL:      cfg.UserInfoURL,
			ClientID:         cfg.ClientID,
			ClientSecret:     string(cfg.ClientSecret),
			RedirectURI:      cfg.RedirectURI,
			Scopes:           cfg.Scopes,
		})

	default:
		return nil, fmt.Errorf("unknown provider type: %s", cfg.Provider)
	}
}
