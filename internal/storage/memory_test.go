package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryStorageDefault(t *testing.T) {
	storage := NewMemoryStorage()
	assert.NotNil(t, storage, "Expected storage to be created")
}
