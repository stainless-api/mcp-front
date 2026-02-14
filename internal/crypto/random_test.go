package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestGenerateSecureToken(t *testing.T) {
	token, err := GenerateSecureToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Each call generates a unique token
	token2, err := GenerateSecureToken()
	assert.NoError(t, err)
	assert.NotEqual(t, token, token2)

	// base64 encoding of 32 bytes should be at least 40 chars
	assert.GreaterOrEqual(t, len(token), 40)
}

func TestHashClientSecret(t *testing.T) {
	secret := "test-client-secret-12345"

	hashed, err := HashClientSecret(secret)
	assert.NoError(t, err)
	assert.NotNil(t, hashed)
	assert.NotEmpty(t, hashed)

	assert.NotEqual(t, []byte(secret), hashed)

	err = bcrypt.CompareHashAndPassword(hashed, []byte(secret))
	assert.NoError(t, err)

	err = bcrypt.CompareHashAndPassword(hashed, []byte("wrong-password"))
	assert.Error(t, err)

	// Same secret produces different hashes due to salt
	hashed2, err := HashClientSecret(secret)
	assert.NoError(t, err)
	assert.NotEqual(t, hashed, hashed2)
}

func TestHashClientSecretIntegration(t *testing.T) {
	secret, err := GenerateSecureToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	hashed, err := HashClientSecret(secret)
	assert.NoError(t, err)

	err = bcrypt.CompareHashAndPassword(hashed, []byte(secret))
	assert.NoError(t, err)
}
