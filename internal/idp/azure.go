package idp

import "fmt"

// NewAzureProvider creates an Azure AD provider using OIDC discovery.
// Azure AD is OIDC-compliant, so we use the generic OIDC provider with Azure's tenant-specific discovery URL.
// Optional direct endpoint overrides (authorizationURL, tokenURL, userInfoURL) skip discovery
// when all three are provided — useful for testing.
func NewAzureProvider(tenantID, clientID, clientSecret, redirectURI, authorizationURL, tokenURL, userInfoURL string) (*OIDCProvider, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenantId is required for Azure AD")
	}

	cfg := OIDCConfig{
		ProviderType: "azure",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Scopes:       []string{"openid", "email", "profile"},
	}

	if authorizationURL != "" && tokenURL != "" && userInfoURL != "" {
		cfg.AuthorizationURL = authorizationURL
		cfg.TokenURL = tokenURL
		cfg.UserInfoURL = userInfoURL
	} else {
		cfg.DiscoveryURL = fmt.Sprintf(
			"https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration",
			tenantID,
		)
	}

	return NewOIDCProvider(cfg)
}
