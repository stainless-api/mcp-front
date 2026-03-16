package inline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_GetCapabilities(t *testing.T) {
	config := Config{
		Description: "Test server",
		Tools: []ToolConfig{
			{
				Name:        "echo",
				Description: "Echo a message",
				InputSchema: json.RawMessage(`{"type": "object", "properties": {"message": {"type": "string"}}}`),
			},
			{
				Name:        "date",
				Description: "Get current date",
				InputSchema: json.RawMessage(`{"type": "object"}`),
			},
		},
	}

	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "echo",
			Description: "Echo a message",
			InputSchema: json.RawMessage(`{"type": "object", "properties": {"message": {"type": "string"}}}`),
			Command:     "echo",
			Args:        []string{"{{.message}}"},
		},
		{
			Name:        "date",
			Description: "Get current date",
			InputSchema: json.RawMessage(`{"type": "object"}`),
			Command:     "date",
		},
	}

	server := NewServer("test", config, resolvedTools)
	capabilities := server.GetCapabilities()

	assert.Len(t, capabilities.Tools, 2)

	echoTool, exists := capabilities.Tools["echo"]
	assert.True(t, exists)
	assert.Equal(t, "echo", echoTool.Name)
	assert.Equal(t, "Echo a message", echoTool.Description)
	assert.NotNil(t, echoTool.InputSchema)

	dateTool, exists := capabilities.Tools["date"]
	assert.True(t, exists)
	assert.Equal(t, "date", dateTool.Name)
	assert.Equal(t, "Get current date", dateTool.Description)
}

func TestServer_HandleToolCall(t *testing.T) {
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "echo",
			Description: "Echo a message",
			Command:     "echo",
			Args:        []string{"test-message"},
		},
		{
			Name:        "cat",
			Description: "Cat a file",
			Command:     "cat",
			Args:        []string{"/nonexistent/file"},
		},
		{
			Name:        "env_test",
			Description: "Test environment",
			Command:     "sh",
			Args:        []string{"-c", "echo TEST_VAR=$TEST_VAR"},
			Env: map[string]string{
				"TEST_VAR": "test-value",
			},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)

	tests := []struct {
		name      string
		toolName  string
		args      map[string]any
		wantError bool
		validate  func(t *testing.T, result any, err error)
	}{
		{
			name:      "echo tool",
			toolName:  "echo",
			args:      map[string]any{},
			wantError: false,
			validate: func(t *testing.T, result any, err error) {
				resultMap, ok := result.(map[string]any)
				require.True(t, ok)
				output := resultMap["output"].(string)
				assert.Equal(t, "test-message\n", output)
			},
		},
		{
			name:      "nonexistent tool",
			toolName:  "nonexistent",
			args:      map[string]any{},
			wantError: true,
			validate: func(t *testing.T, result any, err error) {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "tool nonexistent not found")
			},
		},
		{
			name:      "cat nonexistent file",
			toolName:  "cat",
			args:      map[string]any{},
			wantError: true,
			validate: func(t *testing.T, result any, err error) {
				assert.Error(t, err)
				resultMap, ok := result.(map[string]any)
				require.True(t, ok)
				stderr := resultMap["stderr"].(string)
				assert.Contains(t, stderr, "No such file")
			},
		},
		{
			name:      "environment variable test",
			toolName:  "env_test",
			args:      map[string]any{},
			wantError: false,
			validate: func(t *testing.T, result any, err error) {
				resultMap, ok := result.(map[string]any)
				require.True(t, ok)
				output := resultMap["output"].(string)
				assert.Contains(t, output, "TEST_VAR=test-value")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := server.HandleToolCall(ctx, tt.toolName, tt.args)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tt.validate != nil {
				tt.validate(t, result, err)
			}
		})
	}
}

func TestServer_HandleToolCall_JSON(t *testing.T) {
	// Create a tool that outputs JSON
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "json_output",
			Description: "Output JSON",
			Command:     "echo",
			Args:        []string{`{"status": "ok", "value": 42}`},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)

	ctx := context.Background()
	result, err := server.HandleToolCall(ctx, "json_output", map[string]any{})

	require.NoError(t, err)

	// Should parse as JSON
	resultMap, ok := result.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ok", resultMap["status"])
	assert.Equal(t, float64(42), resultMap["value"])
}

func TestServer_HandleToolCall_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	// Create a tool with a very short timeout
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "slow_command",
			Description: "Slow command",
			Command:     "sleep",
			Args:        []string{"5"},
			Timeout:     "100ms",
		},
	}

	server := NewServer("test", Config{}, resolvedTools)

	ctx := context.Background()
	result, err := server.HandleToolCall(ctx, "slow_command", map[string]any{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "command failed")

	// Check that we got a timeout-related error in stderr or error message
	if resultMap, ok := result.(map[string]any); ok {
		stderr, _ := resultMap["stderr"].(string)
		errorMsg, _ := resultMap["error"].(string)
		// The actual error message varies by OS, but it should indicate termination
		assert.True(t,
			strings.Contains(stderr, "signal") ||
				strings.Contains(stderr, "terminated") ||
				strings.Contains(stderr, "killed") ||
				strings.Contains(errorMsg, "signal") ||
				strings.Contains(errorMsg, "killed"),
			"Expected error to contain signal/terminated/killed, got stderr: %s, error: %s", stderr, errorMsg)
	}
}

func TestServer_HandleToolCall_HTTP_GET(t *testing.T) {
	var receivedQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		assert.Equal(t, http.MethodGet, r.Method)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results": [{"title": "Test Article"}]}`))
	}))
	defer ts.Close()

	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "search",
			Description: "Search",
			HTTP: &ResolvedHTTPConfig{
				Method: "GET",
				URL:    ts.URL + "?type=KNOWLEDGE_ARTICLE&analytics=false",
			},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)
	result, err := server.HandleToolCall(context.Background(), "search", map[string]any{
		"q":     "inventory",
		"limit": 5,
	})

	require.NoError(t, err)

	assert.Contains(t, receivedQuery, "type=KNOWLEDGE_ARTICLE")
	assert.Contains(t, receivedQuery, "analytics=false")
	assert.Contains(t, receivedQuery, "q=inventory")
	assert.Contains(t, receivedQuery, "limit=5")

	resultMap, ok := result.(map[string]any)
	require.True(t, ok)
	results, ok := resultMap["results"].([]any)
	require.True(t, ok)
	assert.Len(t, results, 1)
}

func TestServer_HandleToolCall_HTMLFetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<nav>Nav bar</nav>
			<main id="main-content">
				<h1>Help Article</h1>
				<p>This is the article body.</p>
			</main>
			<footer>Footer</footer>
		</body></html>`))
	}))
	defer ts.Close()

	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "fetch",
			Description: "Fetch article",
			HTMLFetch: &HTMLFetchConfig{
				URLArg:         "url",
				AllowedDomains: []string{"127.0.0.1"},
				Selector:       "#main-content",
			},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)
	result, err := server.HandleToolCall(context.Background(), "fetch", map[string]any{
		"url": ts.URL + "/article",
	})

	require.NoError(t, err)

	text, ok := result.(string)
	require.True(t, ok)
	assert.Contains(t, text, "Help Article")
	assert.Contains(t, text, "This is the article body.")
	assert.NotContains(t, text, "Nav bar")
	assert.NotContains(t, text, "Footer")
}

func TestServer_HandleToolCall_HTMLFetch_DomainValidation(t *testing.T) {
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "fetch",
			Description: "Fetch article",
			HTMLFetch: &HTMLFetchConfig{
				URLArg:         "url",
				AllowedDomains: []string{"help.vori.com"},
				Selector:       "#main-content",
			},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)
	_, err := server.HandleToolCall(context.Background(), "fetch", map[string]any{
		"url": "https://evil.com/phishing",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in the allowed list")
}

func TestServer_HandleToolCall_HTMLFetch_MissingURL(t *testing.T) {
	resolvedTools := []ResolvedToolConfig{
		{
			Name:        "fetch",
			Description: "Fetch article",
			HTMLFetch: &HTMLFetchConfig{
				URLArg:         "url",
				AllowedDomains: []string{"help.vori.com"},
				Selector:       "#main-content",
			},
		},
	}

	server := NewServer("test", Config{}, resolvedTools)
	_, err := server.HandleToolCall(context.Background(), "fetch", map[string]any{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required argument")
}
