package revocation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDenyList(t *testing.T) {
	dl := NewDenyList()

	dl.Add("hash1", time.Now().Add(time.Hour))
	assert.True(t, dl.IsRevoked("hash1"))
	assert.False(t, dl.IsRevoked("hash2"))
}

func TestDenyListExpiry(t *testing.T) {
	dl := NewDenyList()

	dl.Add("hash1", time.Now().Add(-time.Second))
	assert.False(t, dl.IsRevoked("hash1"))
}

func TestDenyListCleanup(t *testing.T) {
	dl := NewDenyList()

	dl.Add("expired", time.Now().Add(-time.Second))
	dl.Add("active", time.Now().Add(time.Hour))

	dl.Cleanup()

	assert.False(t, dl.IsRevoked("expired"))
	assert.True(t, dl.IsRevoked("active"))
}
