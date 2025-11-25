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

	token, err := generator.Generate(
		"user@example.com",
		"exec-123",
		"datadog",
		[]string{"/api/v1/*", "/api/v2/metrics/*"},
		1000,
	)
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

	if claims.UserEmail != "user@example.com" {
		t.Errorf("Expected user email 'user@example.com', got '%s'", claims.UserEmail)
	}
	if claims.ExecutionID != "exec-123" {
		t.Errorf("Expected execution ID 'exec-123', got '%s'", claims.ExecutionID)
	}
	if claims.TargetService != "datadog" {
		t.Errorf("Expected target service 'datadog', got '%s'", claims.TargetService)
	}
	if len(claims.AllowedPaths) != 2 {
		t.Errorf("Expected 2 allowed paths, got %d", len(claims.AllowedPaths))
	}
	if claims.MaxRequests != 1000 {
		t.Errorf("Expected max requests 1000, got %d", claims.MaxRequests)
	}
}

func TestTokenExpiration(t *testing.T) {
	signingKey := []byte("test-signing-key-that-is-at-least-32-bytes-long!!")
	ttl := 1 * time.Millisecond // Very short TTL

	generator := NewGenerator(signingKey, ttl)
	validator := NewValidator(signingKey, ttl)

	token, err := generator.Generate(
		"user@example.com",
		"exec-123",
		"datadog",
		nil,
		0,
	)
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

	token, err := generator.Generate(
		"user@example.com",
		"exec-123",
		"datadog",
		nil,
		0,
	)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = validator.Validate(token)
	if err == nil {
		t.Error("Expected validation to fail with different signing key")
	}
}

func TestGenerateWithMissingFields(t *testing.T) {
	signingKey := []byte("test-signing-key-that-is-at-least-32-bytes-long!!")
	ttl := 5 * time.Minute
	generator := NewGenerator(signingKey, ttl)

	tests := []struct {
		name          string
		userEmail     string
		executionID   string
		targetService string
		expectError   bool
	}{
		{
			name:          "missing user email",
			userEmail:     "",
			executionID:   "exec-123",
			targetService: "datadog",
			expectError:   true,
		},
		{
			name:          "missing execution ID",
			userEmail:     "user@example.com",
			executionID:   "",
			targetService: "datadog",
			expectError:   true,
		},
		{
			name:          "missing target service",
			userEmail:     "user@example.com",
			executionID:   "exec-123",
			targetService: "",
			expectError:   true,
		},
		{
			name:          "all fields present",
			userEmail:     "user@example.com",
			executionID:   "exec-123",
			targetService: "datadog",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generator.Generate(tt.userEmail, tt.executionID, tt.targetService, nil, 0)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
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

func TestTokenWithOptionalFields(t *testing.T) {
	signingKey := []byte("test-signing-key-that-is-at-least-32-bytes-long!!")
	ttl := 5 * time.Minute

	generator := NewGenerator(signingKey, ttl)
	validator := NewValidator(signingKey, ttl)

	// Generate token without optional fields
	token, err := generator.Generate(
		"user@example.com",
		"exec-123",
		"datadog",
		nil, // No allowed paths
		0,   // No max requests
	)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	claims, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.AllowedPaths != nil {
		t.Errorf("Expected nil allowed paths, got %v", claims.AllowedPaths)
	}
	if claims.MaxRequests != 0 {
		t.Errorf("Expected 0 max requests, got %d", claims.MaxRequests)
	}
}
