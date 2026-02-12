package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration validates the complete end-to-end architecture
func TestIntegration(t *testing.T) {
	trace(t, "Starting integration test")

	trace(t, "Waiting for database readiness")
	waitForDB(t)

	trace(t, "Starting mcp-front")
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-test",
		nil,
		map[string]any{"postgres": testPostgresServer(withBearerTokens("test-token", "alt-test-token"), withLogEnabled())},
	)
	startMCPFront(t, writeTestConfig(t, cfg))

	waitForMCPFront(t)
	trace(t, "mcp-front is ready")

	// Get initial container count for cleanup
	initialContainers := getMCPContainers()

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client, "Failed to create MCP client")
	defer client.Close() // Ensure SSE connection is closed

	// Cleanup any containers created during this test
	t.Cleanup(func() {
		cleanupContainers(t, initialContainers)
	})

	err := client.Authenticate()
	require.NoError(t, err, "Authentication failed")

	// For stdio transports, we need to use the proper session-based approach
	t.Log("Testing stdio MCP server...")

	// Connect to the SSE endpoint - this will establish a session
	err = client.Connect()
	require.NoError(t, err, "Failed to connect to MCP server")

	t.Log("Connected to MCP server with session")

	queryParams := map[string]any{
		"name": "execute_sql",
		"arguments": map[string]any{
			"sql": "SELECT COUNT(*) as user_count FROM users",
		},
	}

	result, err := client.SendMCPRequest("tools/call", queryParams)
	require.NoError(t, err, "Failed to execute query")

	t.Logf("Query result: %+v", result)

	require.NotNil(t, result, "Expected some response from MCP server")

	// Check for error in response
	errorMap, hasError := result["error"].(map[string]any)
	assert.False(t, hasError, "Query returned error: %v", errorMap)

	// Verify we got result content
	resultMap, ok := result["result"].(map[string]any)
	require.True(t, ok, "Expected result in response")

	content, ok := resultMap["content"].([]any)
	require.True(t, ok, "Expected content in result")
	assert.NotEmpty(t, content, "Query result missing content")
	t.Log("Query executed successfully")

	// Test tools list
	toolsResult, err := client.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err, "Failed to list tools")

	t.Logf("Tools response: %+v", toolsResult)

	errorMap, hasError = toolsResult["error"].(map[string]any)
	assert.False(t, hasError, "Tools list returned error: %v", errorMap)

	resultMap, ok = toolsResult["result"].(map[string]any)
	require.True(t, ok, "Expected result in tools response")

	tools, ok := resultMap["tools"].([]any)
	require.True(t, ok, "Expected tools array in result")
	assert.NotEmpty(t, tools, "Expected at least one tool")
	t.Logf("Found %d tools", len(tools))

	// Verify execute_sql tool is present
	var toolNames []string
	for _, tool := range tools {
		if toolMap, ok := tool.(map[string]any); ok {
			if name, ok := toolMap["name"].(string); ok {
				toolNames = append(toolNames, name)
			}
		}
	}
	assert.Contains(t, toolNames, "execute_sql", "Should have execute_sql tool")
}
