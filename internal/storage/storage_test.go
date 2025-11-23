package storage

import (
	"context"
	"testing"

	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestMemoryStorageConfidentialClient(t *testing.T) {
	storage := NewMemoryStorage()

	clientID := "test-client-123"
	secret, err := crypto.GenerateClientSecret()
	assert.NoError(t, err)
	hashedSecret, err := crypto.HashClientSecret(secret)
	assert.NoError(t, err)

	redirectURIs := []string{"https://example.com/callback"}
	scopes := []string{"read", "write"}
	issuer := "https://issuer.example.com"

	client, err := storage.CreateConfidentialClient(context.Background(), clientID, hashedSecret, redirectURIs, scopes, issuer)
	assert.NoError(t, err)

	assert.Equal(t, clientID, client.ID)
	assert.Equal(t, hashedSecret, client.Secret)
	assert.Equal(t, redirectURIs, client.RedirectURIs)
	assert.ElementsMatch(t, scopes, client.Scopes)
	assert.ElementsMatch(t, []string{issuer}, client.Audience)
	assert.False(t, client.Public)

	ctx := context.Background()
	storedClient, err := storage.GetClient(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, storedClient)
	assert.Equal(t, clientID, storedClient.GetID())
	assert.False(t, storedClient.IsPublic())

	err = bcrypt.CompareHashAndPassword(storedClient.GetHashedSecret(), []byte(secret))
	assert.NoError(t, err, "Original secret should verify against stored hash")
}

func TestMemoryStoragePublicVsConfidential(t *testing.T) {
	storage := NewMemoryStorage()

	publicClient, err := storage.CreateClient(context.Background(), "public-123", []string{"https://public.com/callback"}, []string{"read"}, "https://issuer.com")
	assert.NoError(t, err)
	assert.True(t, publicClient.Public)
	assert.Nil(t, publicClient.Secret)

	hashedSecret := []byte("hashed-secret")
	confidentialClient, err := storage.CreateConfidentialClient(context.Background(), "confidential-123", hashedSecret, []string{"https://confidential.com/callback"}, []string{"read"}, "https://issuer.com")
	assert.NoError(t, err)
	assert.False(t, confidentialClient.Public)
	assert.NotNil(t, confidentialClient.Secret)
	assert.Equal(t, hashedSecret, confidentialClient.Secret)
}
