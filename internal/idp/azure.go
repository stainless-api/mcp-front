package idp

import "fmt"

// NewAzureProvider creates an Azure AD provider using OIDC discovery.
// Azure AD is OIDC-compliant, so we use the generic OIDC provider with Azure's tenant-specific discovery URL.
func NewAzureProvider(tenantID, clientID, clientSecret, redirectURI string) (*OIDCProvider, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenantId is required for Azure AD")
	}

	discoveryURL := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration",
		tenantID,
	)

	return NewOIDCProvider(OIDCConfig{
		ProviderType: "azure",
		DiscoveryURL: discoveryURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Scopes:       []string{"openid", "email", "profile"},
	})
}
