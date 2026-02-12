package integration

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicAuth(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-basic-auth-test",
		nil,
		map[string]any{"postgres": testPostgresServer(withBasicAuth("admin", "ADMIN_PASSWORD"), withBasicAuth("user", "USER_PASSWORD"))},
	)
	startMCPFront(t, writeTestConfig(t, cfg),
		"ADMIN_PASSWORD=adminpass123",
		"USER_PASSWORD=userpass456",
	)

	// Wait for startup
	waitForMCPFront(t)

	t.Run("valid credentials", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:adminpass123")))
		req.Header.Set("Accept", "text/event-stream")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should get 200 OK with SSE stream when auth passes
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	})

	t.Run("invalid password", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:wrongpass")))

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("unknown user", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("unknown:adminpass123")))

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("access MCP endpoint with basic auth", func(t *testing.T) {
		// Test accessing a protected MCP endpoint
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:userpass456")))
		req.Header.Set("Accept", "text/event-stream")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should get 200 OK with SSE stream when auth passes
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	})

	t.Run("bearer token with basic auth configured", func(t *testing.T) {
		// Server expects basic auth, bearer tokens should fail
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer sometoken")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
