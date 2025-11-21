package integration

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSSEServerIntegration tests the SSE MCP server functionality
func TestSSEServerIntegration(t *testing.T) {
	trace(t, "Starting SSE server integration test")

	// Start mcp-front with SSE config
	trace(t, "Starting mcp-front with SSE config")
	startMCPFront(t, "config/config.sse-test.json")

	waitForMCPFront(t)
	trace(t, "mcp-front is ready")

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client, "Failed to create MCP client")
	defer client.Close()

	client.SetAuthToken("sse-test-token")

	t.Run("SSE connection and message endpoint", func(t *testing.T) {
		// Connect to the SSE server endpoint
		err := client.ConnectToServer("test-sse")
		require.NoError(t, err, "Failed to connect to SSE MCP server")

		t.Log("Connected to SSE MCP server")

		// Let's list available tools first
		params := map[string]any{
			"method": "tools/list",
			"params": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/list", params)
		require.NoError(t, err, "Failed to list tools")

		// Check if we got a result
		assert.NotNil(t, result)
		assert.NotContains(t, result, "error", "Expected no error in response")
	})

	t.Run("SSE tool invocation", func(t *testing.T) {
		// The mock server should provide echo_text tool
		params := map[string]any{
			"name": "echo_text",
			"arguments": map[string]any{
				"text": "Hello from SSE test!",
			},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call echo_text tool")

		// Check for successful response
		if errorMap, hasError := result["error"].(map[string]any); hasError {
			t.Fatalf("Got error response: %v", errorMap)
		}

		// Verify we got a result
		assert.NotNil(t, result["result"])

		// Verify the echo result contains our text
		if resultData, ok := result["result"].(map[string]any); ok {
			if toolResult, ok := resultData["toolResult"].(string); ok {
				assert.Equal(t, "Hello from SSE test!", toolResult)
			}
		}
	})

	t.Run("SSE server disconnection handling", func(t *testing.T) {
		// Simulate server disconnection
		client.Close()

		// Try to reconnect
		err := client.ConnectToServer("test-sse")
		require.NoError(t, err, "Failed to reconnect to SSE server")

		// Verify we can still make requests
		params := map[string]any{
			"method": "tools/list",
			"params": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/list", params)
		require.NoError(t, err, "Failed to list tools after reconnection")
		assert.NotNil(t, result)
	})

	t.Run("SSE streaming functionality", func(t *testing.T) {
		// Test that SSE streaming works by calling the sample_stream tool
		params := map[string]any{
			"name":      "sample_stream",
			"arguments": map[string]any{},
		}

		// The mock server provides sample_stream tool
		result, err := client.SendMCPRequest("tools/call", params)

		require.NoError(t, err, "Connection error during streaming test")
		assert.NotNil(t, result)

		// Verify we got a successful result
		assert.NotContains(t, result, "error", "Should not have error for sample_stream")
		if resultData, ok := result["result"].(map[string]any); ok {
			assert.Equal(t, "Tool executed successfully", resultData["toolResult"])
		}
	})

	t.Run("SSE error handling", func(t *testing.T) {
		// Test calling a non-existent tool
		params := map[string]any{
			"name":      "non_existent_tool_xyz",
			"arguments": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Should not get connection error for non-existent tool")

		// Should get an error in the response
		errorMap, hasError := result["error"].(map[string]any)
		assert.True(t, hasError, "Expected error for non-existent tool")
		if hasError {
			assert.NotEmpty(t, errorMap["message"], "Error should have a message")
		}
	})

	t.Run("Multiple concurrent SSE requests", func(t *testing.T) {
		COUNT := 10

		// Test that we can handle multiple concurrent requests
		done := make(chan bool, COUNT)

		for i := range COUNT {
			go func(index int) {
				defer func() { done <- true }()

				params := map[string]any{
					"name": "echo_text",
					"arguments": map[string]any{
						"text": string(rune('A' + index)),
					},
				}

				result, err := client.SendMCPRequest("tools/call", params)
				assert.NoError(t, err, "Failed concurrent request %d", index)
				assert.NotNil(t, result)
			}(i)
		}

		// Wait for all requests to complete
		timeout := time.After(10 * time.Second)
		for range COUNT {
			select {
			case <-done:
				// Good
			case <-timeout:
				t.Fatal("Timeout waiting for concurrent requests")
			}
		}
	})
}

// TestSSEServerRestart tests SSE server behavior when backend restarts
func TestSSEServerRestart(t *testing.T) {
	trace(t, "Starting SSE server restart test")

	startMCPFront(t, "config/config.sse-test.json")
	waitForMCPFront(t)

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client, "Failed to create MCP client")
	defer client.Close()

	client.SetAuthToken("sse-test-token")

	// Connect initially
	err := client.ConnectToServer("test-sse")
	require.NoError(t, err, "Failed initial connection")

	// Make a successful request
	params := map[string]any{
		"method": "tools/list",
		"params": map[string]any{},
	}

	result, err := client.SendMCPRequest("tools/list", params)
	require.NoError(t, err, "Failed initial request")
	assert.NotNil(t, result)

	// Restart the SSE server
	cmd := exec.Command("docker", "compose", "restart", "test-sse-server")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to restart SSE server: %s", output)

	// Wait for the server to be ready
	time.Sleep(3 * time.Second)

	// Test reconnection behavior
	client.Close()

	// Wait a bit
	time.Sleep(2 * time.Second)

	// Reconnect
	err = client.ConnectToServer("test-sse")
	require.NoError(t, err, "Failed to reconnect after simulated restart")

	// Verify we can make requests again
	result, err = client.SendMCPRequest("tools/list", params)
	require.NoError(t, err, "Failed request after reconnection")
	assert.NotNil(t, result)
}
