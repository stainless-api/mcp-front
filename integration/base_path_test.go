package integration

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasePathRouting(t *testing.T) {
	waitForDB(t)

	cfg := buildTestConfig(
		"http://localhost:8080/mcp-api", "mcp-front-base-path-test",
		nil,
		map[string]any{"postgres": testPostgresServer(withBearerTokens("test-token"))},
	)
	startMCPFront(t, writeTestConfig(t, cfg))
	waitForMCPFront(t)

	initialContainers := getMCPContainers()
	t.Cleanup(func() {
		cleanupContainers(t, initialContainers)
	})

	t.Run("health at root", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("health not under base path", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/mcp-api/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("MCP server at base path", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/mcp-api/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Accept", "text/event-stream")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	})

	t.Run("MCP server not at root", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("Accept", "text/event-stream")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("full MCP connection", func(t *testing.T) {
		client := NewMCPSSEClient("http://localhost:8080/mcp-api")
		client.SetAuthToken("test-token")

		err := client.ConnectToServer("postgres")
		require.NoError(t, err)
		defer client.Close()

		result, err := client.SendMCPRequest("tools/list", map[string]any{})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})
}
