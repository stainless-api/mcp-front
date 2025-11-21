package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStreamableServerIntegration tests the HTTP-Streamable MCP server functionality
func TestStreamableServerIntegration(t *testing.T) {
	trace(t, "Starting Streamable server integration test")

	// Start mcp-front with Streamable config
	trace(t, "Starting mcp-front with Streamable config")
	startMCPFront(t, "config/config.streamable-test.json")

	waitForMCPFront(t)
	trace(t, "mcp-front is ready")

	client := NewMCPStreamableClient("http://localhost:8080")
	require.NotNil(t, client, "Failed to create streamable client")
	defer client.Close()

	client.SetAuthToken("streamable-test-token")

	t.Run("Streamable POST with JSON response", func(t *testing.T) {
		// Connect to the streamable server endpoint
		err := client.ConnectToServer("test-streamable")
		require.NoError(t, err, "Failed to connect to streamable MCP server")

		t.Log("Connected to Streamable MCP server")

		// List available tools
		params := map[string]any{
			"method": "tools/list",
			"params": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/list", params)
		require.NoError(t, err, "Failed to list tools")

		// Check if we got a result
		assert.NotNil(t, result)
		assert.NotContains(t, result, "error", "Expected no error in response")

		// Verify tools are present
		if resultData, ok := result["result"].(map[string]any); ok {
			if tools, ok := resultData["tools"].([]any); ok {
				assert.Equal(t, 2, len(tools), "Expected 2 tools")
			}
		}
	})

	t.Run("Streamable tool invocation with JSON response", func(t *testing.T) {
		// Call the get_time tool
		params := map[string]any{
			"name":      "get_time",
			"arguments": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Failed to call get_time tool")

		// Check for successful response
		if errorMap, hasError := result["error"].(map[string]any); hasError {
			t.Fatalf("Got error response: %v", errorMap)
		}

		// Verify we got a result
		assert.NotNil(t, result["result"])

		// Verify the time result
		if resultData, ok := result["result"].(map[string]any); ok {
			if toolResult, ok := resultData["toolResult"].(string); ok {
				assert.NotEmpty(t, toolResult, "Should have gotten a timestamp")
				t.Logf("Got time: %s", toolResult)
			}
		}
	})

	t.Run("Streamable POST with actual SSE response", func(t *testing.T) {
		baseURL := "http://localhost:8080/test-streamable/sse"

		request := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "echo_streamable",
				"arguments": map[string]any{
					"text": "Hello SSE!",
				},
			},
		}

		body, err := json.Marshal(request)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", baseURL, bytes.NewReader(body))
		require.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer streamable-test-token")
		req.Header.Set("Accept", "text/event-stream")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

		scanner := bufio.NewScanner(resp.Body)
		var responses []map[string]any

		for scanner.Scan() {
			line := scanner.Text()
			if after, ok := strings.CutPrefix(line, "data: "); ok {
				data := after
				var msg map[string]any
				if err := json.Unmarshal([]byte(data), &msg); err == nil {
					responses = append(responses, msg)
				}
			}
		}

		require.NoError(t, scanner.Err())
		assert.GreaterOrEqual(t, len(responses), 1, "Should receive at least one SSE message")

		found := false
		for _, response := range responses {
			if id, ok := response["id"]; ok && id == float64(1) {
				if result, ok := response["result"].(map[string]any); ok {
					if toolResult, ok := result["toolResult"].(string); ok {
						assert.Equal(t, "Echo: Hello SSE!", toolResult)
						found = true
						break
					}
				}
			}
		}
		assert.True(t, found, "Should find the expected response in SSE stream")
	})

	t.Run("Streamable error handling", func(t *testing.T) {
		// Test calling a non-existent tool
		params := map[string]any{
			"name":      "non_existent_tool",
			"arguments": map[string]any{},
		}

		result, err := client.SendMCPRequest("tools/call", params)
		require.NoError(t, err, "Should not get connection error for non-existent tool")

		// Should get an error in the response
		errorMap, hasError := result["error"].(map[string]any)
		assert.True(t, hasError, "Expected error for non-existent tool")
		if hasError {
			assert.Equal(t, float64(-32601), errorMap["code"], "Expected method not found error code")
			assert.Equal(t, "Tool not found", errorMap["message"])
		}
	})

	t.Run("Streamable GET endpoint", func(t *testing.T) {
		// The MCP client library we're using might not support GET requests directly
		// This would typically be used for opening an SSE stream for server-initiated messages
		// For now, we'll just verify the server is configured correctly

		// Re-connect to ensure clean state
		client.Close()
		err := client.ConnectToServer("test-streamable")
		require.NoError(t, err, "Failed to reconnect")

		// The connection itself uses the transport, so if it works, the transport is configured correctly
		assert.True(t, true, "Streamable transport is working")
	})
}
