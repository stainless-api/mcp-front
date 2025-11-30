package idp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitHubProvider_Type(t *testing.T) {
	provider := NewGitHubProvider("client-id", "client-secret", "https://example.com/callback")
	assert.Equal(t, "github", provider.Type())
}

func TestGitHubProvider_AuthURL(t *testing.T) {
	provider := NewGitHubProvider("client-id", "client-secret", "https://example.com/callback")

	authURL := provider.AuthURL("test-state")

	assert.Contains(t, authURL, "github.com")
	assert.Contains(t, authURL, "state=test-state")
	assert.Contains(t, authURL, "client_id=client-id")
}
