package oauth

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/dgellow/mcp-front/internal/urlutil"
)

// Resource Indicators for OAuth 2.0 (RFC 8707)
// https://datatracker.ietf.org/doc/html/rfc8707
//
// This file implements resource indicators which enable clients to specify
// the target service(s) for access tokens. The authorization server includes
// corresponding audience claims in issued tokens, and resource servers validate
// that tokens contain their URI in the audience claim.
//
// Per RFC 8707, the resource parameter indicates the target service using an
// absolute URI. Multiple resource parameters may be included to request access
// to multiple services, though single-resource tokens are recommended for
// better security isolation.

const (
	// MaxResourceParameters limits the number of resource parameters that can be requested
	// in a single authorization request. This prevents DoS attacks via excessive parameter
	// processing while allowing legitimate use cases (large organizations with many services).
	// RFC 8707 recommends single-resource tokens for better security isolation anyway.
	MaxResourceParameters = 100
)

// ExtractResourceParameters extracts resource parameter values from an HTTP request per RFC 8707 Section 2.
// The resource parameter may appear multiple times in the request. Returns empty slice if no resource
// parameters present (not an error - parameter is optional per spec).
//
// Example:
//
//	GET /authorize?resource=https://mcp.company.com/postgres&resource=https://mcp.company.com/linear
//	Returns: []string{"https://mcp.company.com/postgres", "https://mcp.company.com/linear"}
func ExtractResourceParameters(r *http.Request) ([]string, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	resources := r.Form["resource"]
	if len(resources) == 0 {
		return []string{}, nil
	}

	if len(resources) > MaxResourceParameters {
		return nil, fmt.Errorf("too many resource parameters: %d (maximum: %d)", len(resources), MaxResourceParameters)
	}

	// Deduplicate while preserving order
	seen := make(map[string]bool)
	unique := make([]string, 0, len(resources))
	for _, resource := range resources {
		if resource == "" {
			continue
		}
		if !seen[resource] {
			seen[resource] = true
			unique = append(unique, resource)
		}
	}

	return unique, nil
}

// ValidateResourceURI validates a resource URI per RFC 8707 Section 2 requirements.
// The URI MUST be an absolute URI and SHOULD use the https scheme.
// Additionally validates the URI is under the issuer's authority to prevent
// issuing tokens for arbitrary external resources.
//
// Example valid URI: "https://mcp.company.com/postgres"
// Example invalid URI: "/postgres" (not absolute)
// Example invalid URI: "https://external.com/api" (different authority)
func ValidateResourceURI(resourceURI string, issuer string) error {
	u, err := url.Parse(resourceURI)
	if err != nil {
		return fmt.Errorf("resource URI is not a valid URI: %w", err)
	}

	if !u.IsAbs() {
		return fmt.Errorf("resource URI must be absolute (include scheme and host), got: %s", resourceURI)
	}

	if u.Fragment != "" {
		return fmt.Errorf("resource URI must not contain fragment, got: %s", resourceURI)
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("resource URI scheme must be http or https, got: %s", u.Scheme)
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer URI: %w", err)
	}

	if u.Scheme != issuerURL.Scheme {
		return fmt.Errorf("resource URI scheme must match issuer (%s), got: %s", issuerURL.Scheme, u.Scheme)
	}

	if u.Host != issuerURL.Host {
		return fmt.Errorf("resource URI host must match issuer (%s), got: %s", issuerURL.Host, u.Host)
	}

	// Normalize empty issuer path to root for consistent comparison
	issuerPath := issuerURL.Path
	if issuerPath == "" {
		issuerPath = "/"
	}

	// Exact match is always valid (resource can equal issuer)
	if u.Path == issuerPath {
		return nil
	}

	// If issuer is at root, any absolute path is a valid subpath
	if issuerPath == "/" {
		return nil
	}

	// Otherwise, resource path must be a valid subpath of issuer
	// Use issuerPath+"/" to prevent prefix attacks (e.g., "/api" vs "/api-admin")
	if !strings.HasPrefix(u.Path, issuerPath+"/") {
		return fmt.Errorf("resource URI path '%s' is not a valid subpath of issuer path '%s'", u.Path, issuerPath)
	}

	return nil
}

// BuildResourceURI constructs a canonical resource URI for a service per RFC 8707.
// Given issuer "https://mcp.company.com" and service "postgres",
// returns "https://mcp.company.com/postgres".
//
// Example:
//
//	BuildResourceURI("https://mcp.company.com", "postgres")
//	Returns: "https://mcp.company.com/postgres", nil
func BuildResourceURI(issuer string, serviceName string) (string, error) {
	if serviceName == "" {
		return "", fmt.Errorf("service name cannot be empty")
	}

	return urlutil.JoinPath(issuer, serviceName)
}

// ValidateAudienceForService validates that a token's audience claim allows access to the requested service.
// Extracts service name from request path (e.g., "/postgres/sse" → "postgres"),
// builds expected resource URI, and checks if token audience contains it.
//
// Per RFC 8707, tokens MUST only be accepted by resource servers whose URI appears
// in the token's audience claim. This prevents confused deputy attacks where a token
// intended for one service is misused to access another.
//
// Example:
//
//	ValidateAudienceForService("/postgres/sse", []string{"https://mcp.company.com/postgres"}, "https://mcp.company.com")
//	Returns: nil (valid - postgres is in audience)
//
//	ValidateAudienceForService("/linear/sse", []string{"https://mcp.company.com/postgres"}, "https://mcp.company.com")
//	Returns: error (invalid - linear not in audience)
func ValidateAudienceForService(requestPath string, tokenAudience []string, issuer string) error {
	path := strings.TrimPrefix(requestPath, "/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		return fmt.Errorf("request path does not contain service name: %s", requestPath)
	}

	serviceName := parts[0]

	expectedResource, err := BuildResourceURI(issuer, serviceName)
	if err != nil {
		return fmt.Errorf("failed to build resource URI for service %s: %w", serviceName, err)
	}

	if slices.Contains(tokenAudience, expectedResource) {
		return nil
	}

	return fmt.Errorf("token audience %v does not include required resource %s for service %s",
		tokenAudience, expectedResource, serviceName)
}
