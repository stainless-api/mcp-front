package servicecontext

import (
	"context"
)

type contextKey string

const serviceAuthKey contextKey = "auth.service"

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
