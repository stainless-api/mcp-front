package servicecontext

import (
	"context"
)

type contextKey string

const (
	userKey        contextKey = "auth.user"
	serviceAuthKey contextKey = "auth.service"
)

// Info contains service authentication details
type Info struct {
	ServiceName string
	UserToken   string
}

// WithUser adds a username to the context (for basic auth)
func WithUser(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, userKey, username)
}

// GetUser retrieves the username from context (for basic auth)
func GetUser(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(userKey).(string)
	return username, ok
}

// WithAuthInfo adds service authentication info to the context
func WithAuthInfo(ctx context.Context, serviceName, userToken string) context.Context {
	return context.WithValue(ctx, serviceAuthKey, Info{
		ServiceName: serviceName,
		UserToken:   userToken,
	})
}

// GetAuthInfo retrieves service auth info from context
func GetAuthInfo(ctx context.Context) (Info, bool) {
	info, ok := ctx.Value(serviceAuthKey).(Info)
	return info, ok
}

// GetServiceName retrieves the service name from context
func GetServiceName(ctx context.Context) (string, bool) {
	info, ok := GetAuthInfo(ctx)
	if !ok {
		return "", false
	}
	return info.ServiceName, true
}
