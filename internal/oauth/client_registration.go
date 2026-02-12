package oauth

import (
	"fmt"
	"strings"
)

// ParseClientRegistration parses MCP client registration metadata.
// This is provider-agnostic as it deals with MCP client registration, not IDP.
func ParseClientRegistration(metadata map[string]any) (redirectURIs []string, scopes []string, err error) {
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

	scopes = []string{"read", "write"}
	if clientScopes, ok := metadata["scope"].(string); ok {
		if strings.TrimSpace(clientScopes) != "" {
			scopes = strings.Fields(clientScopes)
		}
	}

	return redirectURIs, scopes, nil
}
