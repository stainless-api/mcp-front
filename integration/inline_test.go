package integration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInlineMCPServer tests the inline MCP server functionality
func TestInlineMCPServer(t *testing.T) {
	trace(t, "Starting inline MCP server test")

	// Set environment variable for testing
	os.Setenv("INLINE_TEST_ENV_VAR", "env-value-456")
	defer os.Unsetenv("INLINE_TEST_ENV_VAR")

	trace(t, "Starting mcp-front with inline config")
	startMCPFront(t, "config/config.inline-test.json")

	waitForMCPFront(t)
	trace(t, "mcp-front is ready")

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client, "Failed to create MCP client")
	defer client.Close()

	client.SetAuthToken("inline-test-token")

	// Connect to the inline server SSE endpoint - need custom connection
	err := client.ConnectToServer("test-inline")
	require.NoError(t, err, "Failed to connect to inline MCP server")

	t.Log("Connected to inline MCP server")

	// Test 1: Basic echo tool (static args)
	t.Run("echo tool", func(t *testing.T) {
		params := map[string]any{
			"name": "echo",
			"arguments": map[string]any{
				"message": "Hello, inline MCP!",
			},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call echo tool")

		// Check for error in response
		errorMap, hasError := result["error"].(map[string]any)
		assert.False(t, hasError, "Echo tool returned error: %v", errorMap)

		// Verify result
		resultMap, ok := result["result"].(map[string]any)
		require.True(t, ok, "Expected result in response")

		content, ok := resultMap["content"].([]any)
		require.True(t, ok, "Expected content in result")
		require.NotEmpty(t, content, "Expected content array")

		firstContent, ok := content[0].(map[string]any)
		require.True(t, ok, "Expected content item to be map")

		text, ok := firstContent["text"].(string)
		require.True(t, ok, "Expected text in content")
		// The echo tool has static args, so it outputs "test message"
		assert.Contains(t, text, "test message")
	})

	// Test 2: Environment variables
	t.Run("environment variables", func(t *testing.T) {
		params := map[string]any{
			"name":      "env_test",
			"arguments": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call env_test tool")

		// Check result
		resultMap, _ := result["result"].(map[string]any)
		content, _ := resultMap["content"].([]any)
		firstContent, _ := content[0].(map[string]any)
		text, _ := firstContent["text"].(string)

		// printenv outputs all environment variables
		assert.Contains(t, text, "TEST_VAR=test-value-123", "Static env var not set correctly")
		assert.Contains(t, text, "OTHER_VAR=env-value-456", "Dynamic env var not resolved correctly")
	})

	// Test 3: Static output test
	t.Run("static output", func(t *testing.T) {
		params := map[string]any{
			"name":      "static_test",
			"arguments": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call static_test tool")

		// Check result
		resultMap, _ := result["result"].(map[string]any)
		content, _ := resultMap["content"].([]any)
		firstContent, _ := content[0].(map[string]any)
		text, _ := firstContent["text"].(string)

		assert.Contains(t, text, "Static output: test")
	})

	// Test 4: JSON output parsing
	t.Run("JSON output", func(t *testing.T) {
		params := map[string]any{
			"name": "json_output",
			"arguments": map[string]any{
				"value": "test-input",
			},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call json_output tool")

		// For JSON output, the content should be parsed as JSON
		resultMap, _ := result["result"].(map[string]any)
		content, _ := resultMap["content"].([]any)
		firstContent, _ := content[0].(map[string]any)

		// The JSON output should be in the text field as a string
		text, ok := firstContent["text"].(string)
		require.True(t, ok, "Expected text in content for JSON output")

		// Use testify's JSON assertions
		expectedJSON := `{"status":"ok","input":"static-value","timestamp":1234567890}`
		assert.JSONEq(t, expectedJSON, text)
	})

	// Test 6: Error handling
	t.Run("failing tool", func(t *testing.T) {
		params := map[string]any{
			"name":      "failing_tool",
			"arguments": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Request should succeed even if tool fails")

		// Check for error in response
		errorMap, hasError := result["error"].(map[string]any)
		assert.True(t, hasError, "Expected error for failing tool")

		if hasError {
			code, _ := errorMap["code"].(float64)
			assert.Equal(t, float64(-32603), code, "Expected internal error code")

			message, _ := errorMap["message"].(string)
			assert.Contains(t, message, "command failed")
		}
	})

	// Test 7: List tools
	t.Run("list tools", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/list", map[string]any{})
		require.NoError(t, err, "Failed to list tools")

		// Check result
		resultMap, ok := result["result"].(map[string]any)
		require.True(t, ok, "Expected result in response")

		tools, ok := resultMap["tools"].([]any)
		require.True(t, ok, "Expected tools array")
		assert.Len(t, tools, 6, "Expected 6 tools")

		// Verify tool names
		toolNames := make([]string, 0)
		for _, tool := range tools {
			toolMap, _ := tool.(map[string]any)
			name, _ := toolMap["name"].(string)
			toolNames = append(toolNames, name)
		}

		assert.Contains(t, toolNames, "echo")
		assert.Contains(t, toolNames, "env_test")
		assert.Contains(t, toolNames, "static_test")
		assert.Contains(t, toolNames, "json_output")
		assert.Contains(t, toolNames, "failing_tool")
		assert.Contains(t, toolNames, "slow_tool")
	})
}
