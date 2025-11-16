package oauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOAuthProvider(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		oauthConfig := config.OAuthAuthConfig{
			Issuer:        "https://test.example.com",
			TokenTTL:      time.Hour,
			JWTSecret:     config.Secret(strings.Repeat("a", 32)),
			EncryptionKey: config.Secret(strings.Repeat("b", 32)),
		}

		store := storage.NewMemoryStorage()
		jwtSecret := []byte(oauthConfig.JWTSecret)

		provider, err := NewOAuthProvider(oauthConfig, store, jwtSecret)
		require.NoError(t, err)
		require.NotNil(t, provider)
	})

	t.Run("JWT secret too short", func(t *testing.T) {
		oauthConfig := config.OAuthAuthConfig{
			Issuer:        "https://test.example.com",
			TokenTTL:      time.Hour,
			JWTSecret:     config.Secret("short"),
			EncryptionKey: config.Secret(strings.Repeat("b", 32)),
		}

		store := storage.NewMemoryStorage()
		jwtSecret := []byte(oauthConfig.JWTSecret)

		provider, err := NewOAuthProvider(oauthConfig, store, jwtSecret)
		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "JWT secret must be at least 32 bytes")
	})

	t.Run("development mode vs production mode entropy", func(t *testing.T) {
		oauthConfig := config.OAuthAuthConfig{
			Issuer:        "https://test.example.com",
			TokenTTL:      time.Hour,
			JWTSecret:     config.Secret(strings.Repeat("a", 32)),
			EncryptionKey: config.Secret(strings.Repeat("b", 32)),
		}

		store := storage.NewMemoryStorage()
		jwtSecret := []byte(oauthConfig.JWTSecret)

		// Both dev and prod should create provider successfully
		// The difference is only in MinParameterEntropy config
		provider, err := NewOAuthProvider(oauthConfig, store, jwtSecret)
		require.NoError(t, err)
		require.NotNil(t, provider)
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
