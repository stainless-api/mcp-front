package oauth

import (
	"fmt"
	"strings"
)

// ParseClientRegistration parses MCP client registration metadata and applies
// the configured redirect-URI policy. Each redirect URI must satisfy
// ValidateRedirectURIPolicy: well-formed, absolute, no fragment, hierarchical
// scheme, and (unless allowAny is true) scheme+host(+port) match an entry in
// allowedHosts.
func ParseClientRegistration(metadata map[string]any, allowedHosts []string, allowAny bool) (redirectURIs []string, scopes []string, err error) {
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

	for _, uri := range redirectURIs {
		if err := ValidateRedirectURIPolicy(uri, allowedHosts, allowAny); err != nil {
			return nil, nil, fmt.Errorf("redirect_uri %q rejected: %w", uri, err)
		}
	}

	scopes = []string{"read", "write"}
	if clientScopes, ok := metadata["scope"].(string); ok {
		if strings.TrimSpace(clientScopes) != "" {
			scopes = strings.Fields(clientScopes)
		}
	}

	return redirectURIs, scopes, nil
}
