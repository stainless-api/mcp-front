package storage

import (
	"context"
	"testing"

	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/stretchr/testify/assert"
)

func TestFirestoreStorageConfig(t *testing.T) {
	t.Run("missing GCP project ID", func(t *testing.T) {
		// Test that Firestore storage requires GCP project ID
		ctx := context.Background()
		encryptor, _ := crypto.NewEncryptor([]byte("test-encryption-key-32-bytes-ok!"))

		_, err := NewFirestoreStorage(ctx, "", "(default)", "test_collection", encryptor)
		assert.Error(t, err, "Expected error when GCP project ID is missing for Firestore storage")
		assert.Contains(t, err.Error(), "projectID is required")
	})

	t.Run("missing encryption key", func(t *testing.T) {
		// Test that creating encryptor with invalid key fails
		_, err := crypto.NewEncryptor([]byte("short"))
		assert.Error(t, err, "Expected error when creating encryptor with short key")
		assert.Contains(t, err.Error(), "key must be 32 bytes")
	})

	t.Run("nil encryptor", func(t *testing.T) {
		// Test that Firestore storage requires non-nil encryptor
		ctx := context.Background()

		_, err := NewFirestoreStorage(ctx, "test-project", "(default)", "test_collection", nil)
		assert.Error(t, err, "Expected error when encryptor is nil")
		assert.Contains(t, err.Error(), "encryptor is required")
	})

	t.Run("missing collection", func(t *testing.T) {
		// Test that collection is required
		ctx := context.Background()
		encryptor, _ := crypto.NewEncryptor([]byte("test-encryption-key-32-bytes-ok!"))

		_, err := NewFirestoreStorage(ctx, "test-project", "(default)", "", encryptor)
		assert.Error(t, err, "Expected error when collection is empty")
		assert.Contains(t, err.Error(), "collection is required")
	})
}
