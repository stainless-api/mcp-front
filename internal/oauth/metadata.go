package oauth

import (
	"github.com/dgellow/mcp-front/internal/urlutil"
)

// AuthorizationServerMetadata builds OAuth 2.0 Authorization Server Metadata per RFC 8414
// https://datatracker.ietf.org/doc/html/rfc8414
func AuthorizationServerMetadata(issuer string) (map[string]any, error) {
	authzEndpoint, err := urlutil.JoinPath(issuer, "authorize")
	if err != nil {
		return nil, err
	}

	tokenEndpoint, err := urlutil.JoinPath(issuer, "token")
	if err != nil {
		return nil, err
	}

	registerEndpoint, err := urlutil.JoinPath(issuer, "register")
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": authzEndpoint,
		"token_endpoint":         tokenEndpoint,
		"registration_endpoint":  registerEndpoint,
		"response_types_supported": []string{
			"code",
		},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},
		"code_challenge_methods_supported": []string{
			"S256",
		},
		"token_endpoint_auth_methods_supported": []string{
			"none",
			"client_secret_post",
		},
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},
		"resource_indicators_supported": true,
	}, nil
}

// ProtectedResourceMetadata builds OAuth 2.0 Protected Resource Metadata per RFC 9728
// https://datatracker.ietf.org/doc/html/rfc9728
func ProtectedResourceMetadata(issuer string) (map[string]any, error) {
	authzServerURL, err := urlutil.JoinPath(issuer, ".well-known", "oauth-authorization-server")
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"resource": issuer,
		"authorization_servers": []string{
			issuer,
		},
		"_links": map[string]any{
			"oauth-authorization-server": map[string]string{
				"href": authzServerURL,
			},
		},
	}, nil
}
