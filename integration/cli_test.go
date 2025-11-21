package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIConfigInitGeneratesValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "generated-config.json")

	t.Run("generate and validate config", func(t *testing.T) {
		// Step 1: Generate config with -config-init
		cmd := exec.Command("../cmd/mcp-front/mcp-front", "-config-init", configPath)
		output, err := cmd.CombinedOutput()

		t.Logf("config-init output: %s", output)

		require.NoError(t, err, "config-init should succeed")
		assert.Contains(t, string(output), "Generated default config at:", "should report generation")

		// Verify file was created
		fi, err := os.Stat(configPath)
		require.NoError(t, err, "config file should exist")
		require.Greater(t, fi.Size(), int64(0), "config file should not be empty")

		// Step 2: Validate the generated config
		cmd = exec.Command("../cmd/mcp-front/mcp-front", "-config", configPath, "-validate")
		output, err = cmd.CombinedOutput()

		t.Logf("validate output: %s", output)

		// The generated config should be valid
		require.NoError(t, err, "validate should succeed for config-init generated file")
		assert.Contains(t, string(output), "Result: PASS", "validation should pass")
	})
}
