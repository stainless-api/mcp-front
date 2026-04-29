package servicecontext

import (
	"context"
	"strings"
)

type contextKey string

const serviceAuthKey contextKey = "auth.service"

// IdentityDomain is the synthetic email domain used for service-auth
// identities (`<server>.<name>@serviceauth.mcpfront.alt`). RFC 9476 reserves
// .alt for non-DNS namespaces, so this can never collide with a real user
// email. The OAuth flow rejects any IDP-claimed identity in this domain.
const IdentityDomain = "serviceauth.mcpfront.alt"

// IsReservedDomain reports whether domain is the reserved service-auth
// domain or any subdomain of it. Used by the OAuth flow to reject
// IDP-claimed identities that would impersonate a service-auth principal.
func IsReservedDomain(domain string) bool {
	return domain == IdentityDomain || strings.HasSuffix(domain, "."+IdentityDomain)
}

// Info contains service authentication details.
type Info struct {
	ServiceName string
	UserToken   string
}

// WithAuthInfo adds service authentication info to the context.
func WithAuthInfo(ctx context.Context, serviceName, userToken string) context.Context {
	return context.WithValue(ctx, serviceAuthKey, Info{
		ServiceName: serviceName,
		UserToken:   userToken,
	})
}

// GetAuthInfo retrieves service auth info from context.
func GetAuthInfo(ctx context.Context) (Info, bool) {
	info, ok := ctx.Value(serviceAuthKey).(Info)
	return info, ok
}
