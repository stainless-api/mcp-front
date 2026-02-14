package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// GenerateSecureToken creates a cryptographically secure random token.
// Returns a base64 URL-encoded string suitable for use as OAuth state parameters,
// client IDs, CSRF tokens, etc.
func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HashClientSecret hashes a client secret using bcrypt
// This should be used before storing the secret
func HashClientSecret(secret string) ([]byte, error) {
	// Use default cost (10) for bcrypt
	return bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
}
