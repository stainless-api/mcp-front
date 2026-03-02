package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregateBasic(t *testing.T) {
	mcpServers := map[string]any{
		"test-sse": map[string]any{
			"transportType": "sse",
			"url":           "http://localhost:3001/sse",
		},
		"test-streamable": map[string]any{
			"transportType": "streamable-http",
			"url":           "http://localhost:3002",
		},
		"mcp": map[string]any{
			"type":          "aggregate",
			"transportType": "sse",
			"discovery": map[string]any{
				"timeout":  "10s",
				"cacheTtl": "60s",
			},
		},
	}
	cfg := buildTestConfig("http://localhost:8080", "aggregate-test", nil, mcpServers)
	configPath := writeTestConfig(t, cfg)

	startMCPFront(t, configPath)
	waitForMCPFront(t)

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client)
	defer client.Close()

	t.Run("tool_discovery", func(t *testing.T) {
		err := client.ConnectToServer("mcp")
		require.NoError(t, err, "Failed to connect to aggregate endpoint")

		result, err := client.SendMCPRequest("tools/list", map[string]any{})
		require.NoError(t, err, "Failed to list tools")
		require.NotContains(t, result, "error")

		resultData, ok := result["result"].(map[string]any)
		require.True(t, ok, "Expected result field")
		tools, ok := resultData["tools"].([]any)
		require.True(t, ok, "Expected tools array")

		toolNames := make(map[string]bool)
		for _, tool := range tools {
			toolMap, ok := tool.(map[string]any)
			if ok {
				if name, ok := toolMap["name"].(string); ok {
					toolNames[name] = true
				}
			}
		}

		assert.True(t, toolNames["test-sse.echo_text"], "Missing test-sse.echo_text")
		assert.True(t, toolNames["test-sse.sample_stream"], "Missing test-sse.sample_stream")
		assert.True(t, toolNames["test-streamable.get_time"], "Missing test-streamable.get_time")
		assert.True(t, toolNames["test-streamable.echo_streamable"], "Missing test-streamable.echo_streamable")
		assert.Equal(t, 4, len(toolNames), "Expected exactly 4 tools, got: %v", toolNames)
	})

	t.Run("tool_call_sse_backend", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/call", map[string]any{
			"name":      "test-sse.echo_text",
			"arguments": map[string]any{"text": "hello aggregate"},
		})
		require.NoError(t, err, "Failed to call tool")

		resultData, ok := result["result"].(map[string]any)
		require.True(t, ok, "Expected result field")
		content, ok := resultData["content"].([]any)
		require.True(t, ok, "Expected content array")
		require.NotEmpty(t, content)
		textContent, ok := content[0].(map[string]any)
		require.True(t, ok, "Expected text content object")
		assert.Equal(t, "hello aggregate", textContent["text"])
	})

	t.Run("tool_call_streamable_backend", func(t *testing.T) {
		result, err := client.SendMCPRequest("tools/call", map[string]any{
			"name":      "test-streamable.echo_streamable",
			"arguments": map[string]any{"text": "world"},
		})
		require.NoError(t, err, "Failed to call tool")

		resultData, ok := result["result"].(map[string]any)
		require.True(t, ok, "Expected result field")
		content, ok := resultData["content"].([]any)
		require.True(t, ok, "Expected content array")
		require.NotEmpty(t, content)
		textContent, ok := content[0].(map[string]any)
		require.True(t, ok, "Expected text content object")
		assert.Contains(t, textContent["text"], "Echo: world")
	})
}

func TestAggregatePartialFailure(t *testing.T) {
	mcpServers := map[string]any{
		"test-sse": map[string]any{
			"transportType": "sse",
			"url":           "http://localhost:3001/sse",
		},
		"bad-backend": map[string]any{
			"transportType": "sse",
			"url":           "http://localhost:9999/sse",
		},
		"mcp": map[string]any{
			"type":          "aggregate",
			"transportType": "sse",
			"servers":       []string{"test-sse", "bad-backend"},
			"discovery": map[string]any{
				"timeout":  "3s",
				"cacheTtl": "60s",
			},
		},
	}
	cfg := buildTestConfig("http://localhost:8080", "aggregate-partial-test", nil, mcpServers)
	configPath := writeTestConfig(t, cfg)

	startMCPFront(t, configPath)
	waitForMCPFront(t)

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client)
	defer client.Close()

	err := client.ConnectToServer("mcp")
	require.NoError(t, err, "Failed to connect to aggregate endpoint")

	result, err := client.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err, "Failed to list tools")
	require.NotContains(t, result, "error")

	resultData, ok := result["result"].(map[string]any)
	require.True(t, ok, "Expected result field")
	tools, ok := resultData["tools"].([]any)
	require.True(t, ok, "Expected tools array")

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if ok {
			if name, ok := toolMap["name"].(string); ok {
				toolNames[name] = true
			}
		}
	}

	assert.True(t, toolNames["test-sse.echo_text"], "Missing test-sse.echo_text")
	assert.True(t, toolNames["test-sse.sample_stream"], "Missing test-sse.sample_stream")

	for name := range toolNames {
		assert.NotContains(t, name, "bad-backend", "Should not have tools from unreachable backend")
	}
}

func TestAggregateToolFilter(t *testing.T) {
	mcpServers := map[string]any{
		"test-sse": map[string]any{
			"transportType": "sse",
			"url":           "http://localhost:3001/sse",
			"options": map[string]any{
				"toolFilter": map[string]any{
					"mode": "block",
					"list": []string{"sample_stream"},
				},
			},
		},
		"test-streamable": map[string]any{
			"transportType": "streamable-http",
			"url":           "http://localhost:3002",
		},
		"mcp": map[string]any{
			"type":          "aggregate",
			"transportType": "sse",
			"discovery": map[string]any{
				"timeout":  "10s",
				"cacheTtl": "60s",
			},
		},
	}
	cfg := buildTestConfig("http://localhost:8080", "aggregate-filter-test", nil, mcpServers)
	configPath := writeTestConfig(t, cfg)

	startMCPFront(t, configPath)
	waitForMCPFront(t)

	client := NewMCPSSEClient("http://localhost:8080")
	require.NotNil(t, client)
	defer client.Close()

	err := client.ConnectToServer("mcp")
	require.NoError(t, err, "Failed to connect to aggregate endpoint")

	result, err := client.SendMCPRequest("tools/list", map[string]any{})
	require.NoError(t, err, "Failed to list tools")
	require.NotContains(t, result, "error")

	resultData, ok := result["result"].(map[string]any)
	require.True(t, ok, "Expected result field")
	tools, ok := resultData["tools"].([]any)
	require.True(t, ok, "Expected tools array")

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolMap, ok := tool.(map[string]any)
		if ok {
			if name, ok := toolMap["name"].(string); ok {
				toolNames[name] = true
			}
		}
	}

	assert.True(t, toolNames["test-sse.echo_text"], "echo_text should be present")
	assert.False(t, toolNames["test-sse.sample_stream"], "sample_stream should be blocked by filter")

	assert.True(t, toolNames["test-streamable.get_time"], "get_time should be unaffected")
	assert.True(t, toolNames["test-streamable.echo_streamable"], "echo_streamable should be unaffected")
}
