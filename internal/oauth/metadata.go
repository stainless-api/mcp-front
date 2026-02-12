package oauth

import (
	"strings"

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

// AuthorizationServerMetadataURI returns the well-known URI for the authorization server metadata.
func AuthorizationServerMetadataURI(issuer string) (string, error) {
	return urlutil.JoinPath(issuer, ".well-known", "oauth-authorization-server")
}

// ServiceProtectedResourceMetadata builds OAuth 2.0 Protected Resource Metadata per RFC 9728
// for a specific service. Per RFC 9728 Section 5.2, multiple resources on a single host
// use path-based differentiation, with each resource having its own metadata endpoint.
//
// Example:
//
//	ServiceProtectedResourceMetadata("https://mcp.company.com", "postgres")
//	Returns: {"resource": "https://mcp.company.com/postgres", ...}
func ServiceProtectedResourceMetadata(issuer string, serviceName string) (map[string]any, error) {
	resourceURI, err := urlutil.JoinPath(issuer, serviceName)
	if err != nil {
		return nil, err
	}

	authzServerURL, err := AuthorizationServerMetadataURI(issuer)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"resource": resourceURI,
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

// ServiceProtectedResourceMetadataURI builds the URI for a service-specific protected
// resource metadata endpoint per RFC 9728. Used in WWW-Authenticate headers to direct
// clients to the correct per-service metadata endpoint.
//
// Example:
//
//	ServiceProtectedResourceMetadataURI("https://mcp.company.com", "postgres")
//	Returns: "https://mcp.company.com/.well-known/oauth-protected-resource/postgres"
func ServiceProtectedResourceMetadataURI(issuer string, serviceName string) (string, error) {
	return urlutil.JoinPath(issuer, ".well-known", "oauth-protected-resource", serviceName)
}

// ClientMetadata represents OAuth 2.0 client metadata
type ClientMetadata struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// BuildClientMetadata creates client metadata for public discovery
func BuildClientMetadata(clientID string, redirectURIs []string, grantTypes []string, responseTypes []string, scopes []string, tokenEndpointAuthMethod string, issuedAt int64) ClientMetadata {
	return ClientMetadata{
		ClientID:                clientID,
		ClientIDIssuedAt:        issuedAt,
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scope:                   strings.Join(scopes, " "),
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
	}
}
