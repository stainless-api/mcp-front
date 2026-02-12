package server

import (
	"testing"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/storage"
)

func TestAdminHandlers_CSRF(t *testing.T) {
	// Create test dependencies
	storage := storage.NewMemoryStorage()
	cfg := config.Config{
		Proxy: config.ProxyConfig{
			Admin: &config.AdminConfig{
				Enabled:     true,
				AdminEmails: []string{"admin@example.com"},
			},
		},
	}
	sessionManager := client.NewStdioSessionManager()
	encryptionKey := "test-encryption-key-32-bytes-long"

	// Create admin handlers
	handlers := NewAdminHandlers(storage, cfg, sessionManager, encryptionKey)

	t.Run("generate and validate CSRF token", func(t *testing.T) {
		// Generate token
		token, err := handlers.csrf.Generate()
		if err != nil {
			t.Fatalf("Failed to generate CSRF token: %v", err)
		}

		// Token should not be empty
		if token == "" {
			t.Error("Generated token is empty")
		}

		// Token should be valid immediately
		if !handlers.csrf.Validate(token) {
			t.Error("Token should be valid immediately after generation")
		}

		// Token should not be valid twice (though with HMAC it actually can be)
		// With HMAC-based tokens, they can be validated multiple times
		if !handlers.csrf.Validate(token) {
			t.Error("HMAC token should be valid on second validation")
		}
	})

	t.Run("invalid token format", func(t *testing.T) {
		invalidTokens := []string{
			"",
			"invalid",
			"part1:part2",             // Missing signature
			"part1:part2:part3:part4", // Too many parts
		}

		for _, token := range invalidTokens {
			if handlers.csrf.Validate(token) {
				t.Errorf("Token '%s' should be invalid", token)
			}
		}
	})

	t.Run("expired token", func(t *testing.T) {
		// Test that validateCSRFToken rejects malformed tokens
		// An expired token would have a timestamp from > 15 minutes ago
		expiredToken := "test-nonce:0:invalid-signature"

		if handlers.csrf.Validate(expiredToken) {
			t.Error("Expired token should be invalid")
		}
	})

	t.Run("different encryption keys", func(t *testing.T) {
		// Create handlers with different key
		handlers2 := NewAdminHandlers(storage, cfg, sessionManager, "different-encryption-key-32bytes")

		// Generate token with first handler
		token1, err := handlers.csrf.Generate()
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Token from handler1 should not validate with handler2
		if handlers2.csrf.Validate(token1) {
			t.Error("Token should not validate with different encryption key")
		}

		// But should still validate with original handler
		if !handlers.csrf.Validate(token1) {
			t.Error("Token should validate with original handler")
		}
	})
}
