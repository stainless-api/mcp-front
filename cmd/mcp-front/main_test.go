package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratedConfigValidates(t *testing.T) {
	// Create a temporary directory for test
	tmpDir, err := os.MkdirTemp("", "mcp-front-test")
	require.NoError(t, err, "Failed to create temp dir")
	defer os.RemoveAll(tmpDir)

	// Generate config file
	configPath := filepath.Join(tmpDir, "test-config.json")
	err = generateDefaultConfig(configPath)
	require.NoError(t, err, "Failed to generate default config")

	// Validate the generated config
	result, err := config.ValidateFile(configPath)
	require.NoError(t, err, "Failed to validate config")

	// Check for validation errors
	assert.Empty(t, result.Errors, "Generated config should have no validation errors")

	// Check for validation warnings
	assert.Empty(t, result.Warnings, "Generated config should have no validation warnings")
}
