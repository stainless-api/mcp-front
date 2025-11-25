package executiontoken

import (
	"testing"
	"time"
)

func TestTokenGenerationAndValidation(t *testing.T) {
	signingKey := []byte("test-signing-key-that-is-at-least-32-bytes-long!!")
	ttl := 5 * time.Minute

	generator := NewGenerator(signingKey, ttl)
	validator := NewValidator(signingKey, ttl)

	sessionID := "sess_abc123"
	token, err := generator.Generate(sessionID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Fatal("Generated token is empty")
	}

	claims, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.SessionID != sessionID {
		t.Errorf("Expected session ID '%s', got '%s'", sessionID, claims.SessionID)
	}

	if claims.IssuedAt.IsZero() {
		t.Error("Expected IssuedAt to be set")
	}

	if time.Since(claims.IssuedAt) > 1*time.Second {
		t.Errorf("Expected IssuedAt to be recent, got %v", claims.IssuedAt)
	}
}

func TestTokenExpiration(t *testing.T) {
	signingKey := []byte("test-signing-key-that-is-at-least-32-bytes-long!!")
	ttl := 1 * time.Millisecond // Very short TTL

	generator := NewGenerator(signingKey, ttl)
	validator := NewValidator(signingKey, ttl)

	token, err := generator.Generate("sess_abc123")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, err = validator.Validate(token)
	if err == nil {
		t.Error("Expected validation to fail for expired token")
	}
}

func TestTokenWithDifferentSigningKey(t *testing.T) {
	signingKey1 := []byte("test-signing-key-1-at-least-32-bytes-long!!!")
	signingKey2 := []byte("test-signing-key-2-at-least-32-bytes-long!!!")
	ttl := 5 * time.Minute

	generator := NewGenerator(signingKey1, ttl)
	validator := NewValidator(signingKey2, ttl)

	token, err := generator.Generate("sess_abc123")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = validator.Validate(token)
	if err == nil {
		t.Error("Expected validation to fail with different signing key")
	}
}

func TestGenerateWithMissingSessionID(t *testing.T) {
	signingKey := []byte("test-signing-key-that-is-at-least-32-bytes-long!!")
	ttl := 5 * time.Minute
	generator := NewGenerator(signingKey, ttl)

	_, err := generator.Generate("")
	if err == nil {
		t.Error("Expected error when session ID is empty")
	}
}

func TestValidateEmptyToken(t *testing.T) {
	signingKey := []byte("test-signing-key-that-is-at-least-32-bytes-long!!")
	ttl := 5 * time.Minute
	validator := NewValidator(signingKey, ttl)

	_, err := validator.Validate("")
	if err == nil {
		t.Error("Expected validation to fail for empty token")
	}
}

func TestValidateMalformedToken(t *testing.T) {
	signingKey := []byte("test-signing-key-that-is-at-least-32-bytes-long!!")
	ttl := 5 * time.Minute
	validator := NewValidator(signingKey, ttl)

	_, err := validator.Validate("not-a-valid-token")
	if err == nil {
		t.Error("Expected validation to fail for malformed token")
	}
}
