package oauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthorizationServer(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		server, err := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret:       []byte(strings.Repeat("a", 32)),
			Issuer:          "https://test.example.com",
			AccessTokenTTL:  time.Hour,
			RefreshTokenTTL: 30 * 24 * time.Hour,
		})
		require.NoError(t, err)
		require.NotNil(t, server)
	})

	t.Run("JWT secret too short", func(t *testing.T) {
		server, err := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret: []byte("short"),
			Issuer:    "https://test.example.com",
		})
		assert.Error(t, err)
		assert.Nil(t, server)
		assert.Contains(t, err.Error(), "JWT secret must be at least 32 bytes")
	})

	t.Run("defaults applied", func(t *testing.T) {
		server, err := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret: []byte(strings.Repeat("a", 32)),
			Issuer:    "https://test.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, server)
		assert.Equal(t, time.Hour, server.accessTokenTTL)
		assert.Equal(t, 30*24*time.Hour, server.refreshTokenTTL)
		assert.Equal(t, 10*time.Minute, server.codeLifespan)
	})

	t.Run("min state entropy configurable", func(t *testing.T) {
		server, err := NewAuthorizationServer(AuthorizationServerConfig{
			JWTSecret:       []byte(strings.Repeat("a", 32)),
			Issuer:          "https://test.example.com",
			MinStateEntropy: 8,
		})
		require.NoError(t, err)
		assert.Equal(t, 8, server.minStateEntropy)
	})
}

func TestGenerateJWTSecret(t *testing.T) {
	t.Run("provided secret is used", func(t *testing.T) {
		provided := strings.Repeat("a", 32)
		secret, err := GenerateJWTSecret(provided)
		require.NoError(t, err)
		assert.Equal(t, []byte(provided), secret)
	})

	t.Run("generated secret when not provided", func(t *testing.T) {
		secret, err := GenerateJWTSecret("")
		require.NoError(t, err)
		assert.Len(t, secret, 32, "Generated secret should be 32 bytes")
	})

	t.Run("generated secrets are random", func(t *testing.T) {
		secret1, err1 := GenerateJWTSecret("")
		secret2, err2 := GenerateJWTSecret("")

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, secret1, secret2, "Generated secrets should be different")
	})
}

func TestNewSessionEncryptor(t *testing.T) {
	t.Run("valid encryption key", func(t *testing.T) {
		key := []byte(strings.Repeat("a", 32))
		encryptor, err := NewSessionEncryptor(key)

		require.NoError(t, err)
		require.NotNil(t, encryptor)

		// Test encrypt/decrypt round trip
		plaintext := "test-session-data"
		encrypted, err := encryptor.Encrypt(plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, encrypted)

		decrypted, err := encryptor.Decrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encryption key too short", func(t *testing.T) {
		key := []byte("short")
		encryptor, err := NewSessionEncryptor(key)

		assert.Error(t, err)
		assert.Nil(t, encryptor)
	})
}

func TestGetUserFromContext(t *testing.T) {
	t.Run("user in context", func(t *testing.T) {
		ctx := context.Background()
		ctx = context.WithValue(ctx, GetUserContextKey(), "user@example.com")

		email, ok := GetUserFromContext(ctx)
		assert.True(t, ok)
		assert.Equal(t, "user@example.com", email)
	})

	t.Run("no user in context", func(t *testing.T) {
		ctx := context.Background()

		email, ok := GetUserFromContext(ctx)
		assert.False(t, ok)
		assert.Empty(t, email)
	})
}

func TestExtractServiceNameFromPath(t *testing.T) {
	tests := []struct {
		name        string
		requestPath string
		issuer      string
		want        string
	}{
		{
			name:        "simple path",
			requestPath: "/postgres/sse",
			issuer:      "https://mcp.company.com",
			want:        "postgres",
		},
		{
			name:        "path with message endpoint",
			requestPath: "/linear/message",
			issuer:      "https://mcp.company.com",
			want:        "linear",
		},
		{
			name:        "path with base path in issuer",
			requestPath: "/mcp/postgres/sse",
			issuer:      "https://mcp.company.com/mcp",
			want:        "postgres",
		},
		{
			name:        "issuer with trailing slash",
			requestPath: "/gong/sse",
			issuer:      "https://mcp.company.com/",
			want:        "gong",
		},
		{
			name:        "deeply nested path",
			requestPath: "/postgres/sse/some/more/path",
			issuer:      "https://mcp.company.com",
			want:        "postgres",
		},
		{
			name:        "empty path",
			requestPath: "/",
			issuer:      "https://mcp.company.com",
			want:        "",
		},
		{
			name:        "path equals base path",
			requestPath: "/mcp",
			issuer:      "https://mcp.company.com/mcp",
			want:        "",
		},
		{
			name:        "invalid issuer URL",
			requestPath: "/postgres/sse",
			issuer:      "://invalid",
			want:        "",
		},
		{
			name:        "path outside base path",
			requestPath: "/health",
			issuer:      "https://mcp.company.com/api",
			want:        "",
		},
		{
			name:        "path with similar prefix to base path",
			requestPath: "/api-v2/postgres/sse",
			issuer:      "https://mcp.company.com/api",
			want:        "",
		},
		{
			name:        "well-known path outside base path",
			requestPath: "/.well-known/oauth-authorization-server",
			issuer:      "https://mcp.company.com/mcp",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractServiceNameFromPath(tt.requestPath, tt.issuer)
			assert.Equal(t, tt.want, got)
		})
	}
}
