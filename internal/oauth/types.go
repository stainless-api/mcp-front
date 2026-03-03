package oauth

import "context"

// contextKey is the type used for context keys to avoid collisions
type contextKey string

const authTokenContextKey contextKey = "auth_token"

func GetAuthTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(authTokenContextKey).(string)
	return token, ok
}

func WithAuthToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authTokenContextKey, token)
}
