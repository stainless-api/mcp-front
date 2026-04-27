package oauth

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type Client interface {
	GetID() string
	GetSecret() []byte
	GetRedirectURIs() []string
	GetScopes() []string
	GetAudience() []string
	IsPublic() bool
}

func ValidateRedirectURI(redirectURI string, client Client) error {
	if !slices.Contains(client.GetRedirectURIs(), redirectURI) {
		return fmt.Errorf("redirect_uri not registered for this client")
	}
	return nil
}

// ValidateRequestedRedirectURI checks the redirect_uri supplied with an
// authorize request: it must be present, registered for the client, and
// satisfy the configured host-allowlist policy.
//
// This MUST run before any other authorize-request validation. Callers that
// receive an error here MUST return a direct error response and MUST NOT 302
// the user-agent to the supplied URI (RFC 6749 §3.1.2.4 forbids redirecting
// when the redirect_uri itself is the validation failure).
func ValidateRequestedRedirectURI(redirectURI string, client Client, allowedHosts []string, allowAny bool) error {
	if redirectURI == "" {
		return fmt.Errorf("redirect_uri is required")
	}
	if err := ValidateRedirectURI(redirectURI, client); err != nil {
		return err
	}
	if err := ValidateRedirectURIPolicy(redirectURI, allowedHosts, allowAny); err != nil {
		return err
	}
	return nil
}

// ValidateRedirectURIPolicy checks that a redirect URI is well-formed and,
// unless allowAny is set, that its scheme + host (+ port if the entry
// specifies one) match an entry in the configured allowlist. Each allowlist
// entry is an origin in the form "scheme://host[:port]". An entry without a
// port matches any port for that host; an entry with a port matches only
// that exact port. Hostname matching is case-insensitive per RFC 3986 §3.2.2.
//
// Structural checks apply regardless of allowAny:
//   - must be an absolute URI (RFC 6749 §3.1.2)
//   - must not contain a fragment (RFC 6749 §3.1.2)
//   - must have a host
//   - must not be an opaque URI (no "//" authority component)
//
// The opaque-URI rejection is a hardening choice on top of the RFC. It
// catches the everyday form of "javascript:" and "data:" URIs (which are
// opaque). It does NOT enforce a scheme allowlist — scheme policy is the
// allowlist's job. An operator who explicitly lists "ftp://example.com" or
// "myapp://callback" in allowedHosts is opting into that scheme.
func ValidateRedirectURIPolicy(uri string, allowedHosts []string, allowAny bool) error {
	if uri == "" {
		return fmt.Errorf("redirect URI is empty")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("redirect URI is not a valid URI: %w", err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("redirect URI must be absolute, got: %s", uri)
	}
	if u.Opaque != "" {
		return fmt.Errorf("redirect URI scheme %q is not allowed (only hierarchical schemes are supported)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("redirect URI must have a host, got: %s", uri)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("redirect URI must not contain a fragment, got: %s", uri)
	}

	if allowAny {
		return nil
	}

	for _, entry := range allowedHosts {
		eu, err := url.Parse(entry)
		if err != nil {
			continue
		}
		if !strings.EqualFold(eu.Scheme, u.Scheme) {
			continue
		}
		if !strings.EqualFold(eu.Hostname(), u.Hostname()) {
			continue
		}
		if eu.Port() != "" && eu.Port() != u.Port() {
			continue
		}
		return nil
	}
	return fmt.Errorf("redirect URI %q is not allowed by the configured host allowlist", uri)
}

func ValidateClientSecret(providedSecret string, client Client) error {
	if client.IsPublic() {
		return nil
	}
	if err := bcrypt.CompareHashAndPassword(client.GetSecret(), []byte(providedSecret)); err != nil {
		return fmt.Errorf("invalid client secret")
	}
	return nil
}
