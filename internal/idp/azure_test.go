package idp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAzureProvider_MissingTenantID(t *testing.T) {
	_, err := NewAzureProvider("", "client-id", "client-secret", "https://example.com/callback")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenantId is required")
}
