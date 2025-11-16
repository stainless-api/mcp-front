package servicecontext

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithAuthInfoAndGetAuthInfo(t *testing.T) {
	t.Run("set and retrieve auth info", func(t *testing.T) {
		ctx := context.Background()

		ctx = WithAuthInfo(ctx, "test-service", "test-user-token")

		retrieved, ok := GetAuthInfo(ctx)
		assert.True(t, ok)
		assert.Equal(t, "test-service", retrieved.ServiceName)
		assert.Equal(t, "test-user-token", retrieved.UserToken)
	})

	t.Run("get auth info when not set", func(t *testing.T) {
		ctx := context.Background()

		retrieved, ok := GetAuthInfo(ctx)
		assert.False(t, ok)
		assert.Equal(t, Info{}, retrieved)
	})

	t.Run("overwrite existing auth info", func(t *testing.T) {
		ctx := context.Background()

		ctx = WithAuthInfo(ctx, "service-1", "token-1")
		ctx = WithAuthInfo(ctx, "service-2", "token-2")

		retrieved, ok := GetAuthInfo(ctx)
		assert.True(t, ok)
		assert.Equal(t, "service-2", retrieved.ServiceName)
		assert.Equal(t, "token-2", retrieved.UserToken)
	})
}

func TestWithUserAndGetUser(t *testing.T) {
	t.Run("set and retrieve user", func(t *testing.T) {
		ctx := context.Background()

		ctx = WithUser(ctx, "test-user")

		user, ok := GetUser(ctx)
		assert.True(t, ok)
		assert.Equal(t, "test-user", user)
	})

	t.Run("get user when not set", func(t *testing.T) {
		ctx := context.Background()

		user, ok := GetUser(ctx)
		assert.False(t, ok)
		assert.Empty(t, user)
	})
}

func TestGetServiceName(t *testing.T) {
	t.Run("get service name from context", func(t *testing.T) {
		ctx := context.Background()
		ctx = WithAuthInfo(ctx, "my-service", "token-123")

		serviceName, ok := GetServiceName(ctx)
		assert.True(t, ok)
		assert.Equal(t, "my-service", serviceName)
	})

	t.Run("get service name when not set", func(t *testing.T) {
		ctx := context.Background()

		serviceName, ok := GetServiceName(ctx)
		assert.False(t, ok)
		assert.Empty(t, serviceName)
	})
}
