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

	// Test resources list
	resourcesResult, err := client.SendMCPRequest("resources/list", map[string]any{})
	require.NoError(t, err, "Failed to list resources")

	t.Logf("Resources response: %+v", resourcesResult)

	// Check for error in resources response
	errorMap, hasError = resourcesResult["error"].(map[string]any)
	assert.False(t, hasError, "Resources list returned error: %v", errorMap)

	// Verify we got resources
	resultMap, ok = resourcesResult["result"].(map[string]any)
	require.True(t, ok, "Expected result in resources response")

	resources, ok := resultMap["resources"].([]any)
	require.True(t, ok, "Expected resources array in result")
	assert.NotEmpty(t, resources, "Expected at least one resource")
	t.Logf("Found %d resources", len(resources))

}
