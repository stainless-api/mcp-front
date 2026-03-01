package gateway

import (
	"context"
	"fmt"
	"testing"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockMCPClient struct {
	tools      []mcp.Tool
	callResult *mcp.CallToolResult
	callErr    error
	closed     bool
}

func (m *mockMCPClient) Initialize(_ context.Context, _ mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	return &mcp.InitializeResult{}, nil
}

func (m *mockMCPClient) ListTools(_ context.Context, _ mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	return &mcp.ListToolsResult{Tools: m.tools}, nil
}

func (m *mockMCPClient) CallTool(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if m.callErr != nil {
		return nil, m.callErr
	}
	if m.callResult != nil {
		return m.callResult, nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("called %s", req.Params.Name)), nil
}

func (m *mockMCPClient) ListPrompts(_ context.Context, _ mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error) {
	return &mcp.ListPromptsResult{}, nil
}

func (m *mockMCPClient) GetPrompt(_ context.Context, _ mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{}, nil
}

func (m *mockMCPClient) ListResources(_ context.Context, _ mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error) {
	return &mcp.ListResourcesResult{}, nil
}

func (m *mockMCPClient) ReadResource(_ context.Context, _ mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{}, nil
}

func (m *mockMCPClient) ListResourceTemplates(_ context.Context, _ mcp.ListResourceTemplatesRequest) (*mcp.ListResourceTemplatesResult, error) {
	return &mcp.ListResourceTemplatesResult{}, nil
}

func (m *mockMCPClient) Ping(_ context.Context) error { return nil }

func (m *mockMCPClient) Start(_ context.Context) error { return nil }

func (m *mockMCPClient) Close() error {
	m.closed = true
	return nil
}

func newTestServer(mocks map[string]*mockMCPClient) *Server {
	configs := make(map[string]*config.MCPClientConfig)
	for name := range mocks {
		configs[name] = &config.MCPClientConfig{
			TransportType: config.MCPClientTypeStdio,
			Command:       "echo",
		}
	}

	creator := func(name string, _ *config.MCPClientConfig) (client.MCPClientInterface, error) {
		m, ok := mocks[name]
		if !ok {
			return nil, fmt.Errorf("no mock for %s", name)
		}
		return m, nil
	}

	return newServer(configs, nil, nil, "http://localhost:8080", creator)
}

func TestServer_HandleInitialize(t *testing.T) {
	s := newTestServer(map[string]*mockMCPClient{})
	result := s.HandleInitialize("user@example.com")

	assert.Equal(t, "2025-11-25", result["protocolVersion"])
	serverInfo := result["serverInfo"].(map[string]any)
	assert.Equal(t, "gateway", serverInfo["name"])
}

func TestServer_HandleToolsList(t *testing.T) {
	mocks := map[string]*mockMCPClient{
		"postgres": {
			tools: []mcp.Tool{
				{Name: "query_db", Description: "Execute SQL"},
			},
		},
		"linear": {
			tools: []mcp.Tool{
				{Name: "create_issue", Description: "Create an issue"},
				{Name: "list_issues", Description: "List issues"},
			},
		},
	}

	s := newTestServer(mocks)
	ctx := context.Background()

	tools, err := s.HandleToolsList(ctx, "user@example.com")
	require.NoError(t, err)
	assert.Len(t, tools, 3)

	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool["name"].(string)] = true
	}
	assert.True(t, names["postgres__query_db"])
	assert.True(t, names["linear__create_issue"])
	assert.True(t, names["linear__list_issues"])
}

func TestServer_HandleToolsList_Caching(t *testing.T) {
	callCount := 0
	mock := &mockMCPClient{
		tools: []mcp.Tool{{Name: "tool1"}},
	}

	configs := map[string]*config.MCPClientConfig{
		"svc": {TransportType: config.MCPClientTypeStdio, Command: "echo"},
	}

	creator := func(_ string, _ *config.MCPClientConfig) (client.MCPClientInterface, error) {
		callCount++
		return mock, nil
	}

	s := newServer(configs, nil, nil, "http://localhost:8080", creator)
	ctx := context.Background()

	tools1, err := s.HandleToolsList(ctx, "user@example.com")
	require.NoError(t, err)
	assert.Len(t, tools1, 1)

	tools2, err := s.HandleToolsList(ctx, "user@example.com")
	require.NoError(t, err)
	assert.Len(t, tools2, 1)

	assert.Equal(t, 1, callCount, "should reuse cached connection")
}

func TestServer_HandleToolCall(t *testing.T) {
	mocks := map[string]*mockMCPClient{
		"postgres": {
			tools: []mcp.Tool{{Name: "query_db"}},
		},
	}

	s := newTestServer(mocks)
	ctx := context.Background()

	result, err := s.HandleToolCall(ctx, "user@example.com", "postgres__query_db", map[string]any{"sql": "SELECT 1"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestServer_HandleToolCall_UnknownService(t *testing.T) {
	s := newTestServer(map[string]*mockMCPClient{})

	_, err := s.HandleToolCall(context.Background(), "user@example.com", "unknown__tool", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown service")
}

func TestServer_HandleToolCall_InvalidName(t *testing.T) {
	s := newTestServer(map[string]*mockMCPClient{})

	_, err := s.HandleToolCall(context.Background(), "user@example.com", "no_separator", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tool name")
}

func TestServer_HandleToolsList_BackendFailure(t *testing.T) {
	configs := map[string]*config.MCPClientConfig{
		"good": {TransportType: config.MCPClientTypeStdio, Command: "echo"},
		"bad":  {TransportType: config.MCPClientTypeStdio, Command: "echo"},
	}

	goodMock := &mockMCPClient{
		tools: []mcp.Tool{{Name: "tool1"}},
	}

	creator := func(name string, _ *config.MCPClientConfig) (client.MCPClientInterface, error) {
		if name == "bad" {
			return nil, fmt.Errorf("connection refused")
		}
		return goodMock, nil
	}

	s := newServer(configs, nil, nil, "http://localhost:8080", creator)

	tools, err := s.HandleToolsList(context.Background(), "user@example.com")
	require.NoError(t, err)
	assert.Len(t, tools, 1)
	assert.Equal(t, "good__tool1", tools[0]["name"])
}

func TestServer_Shutdown(t *testing.T) {
	mock := &mockMCPClient{
		tools: []mcp.Tool{{Name: "tool1"}},
	}
	mocks := map[string]*mockMCPClient{"svc": mock}

	s := newTestServer(mocks)

	_, err := s.HandleToolsList(context.Background(), "user@example.com")
	require.NoError(t, err)

	s.Shutdown()
	assert.True(t, mock.closed)
}

func TestServer_UserTokenRequired(t *testing.T) {
	configs := map[string]*config.MCPClientConfig{
		"linear": {
			TransportType:     config.MCPClientTypeStreamable,
			URL:               "https://mcp.linear.app/mcp",
			RequiresUserToken: true,
		},
	}

	tokenCalled := false
	getUserToken := func(_ context.Context, _, _ string, _ *config.MCPClientConfig) (string, error) {
		tokenCalled = true
		return "user-oauth-token", nil
	}

	mock := &mockMCPClient{
		tools: []mcp.Tool{{Name: "create_issue"}},
	}

	creator := func(_ string, _ *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return mock, nil
	}

	s := newServer(configs, nil, getUserToken, "http://localhost:8080", creator)

	tools, err := s.HandleToolsList(context.Background(), "user@example.com")
	require.NoError(t, err)
	assert.Len(t, tools, 1)
	assert.True(t, tokenCalled)
}
