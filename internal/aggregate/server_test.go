package aggregate

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTransport implements client.MCPClientInterface for testing.
type mockTransport struct {
	mu            sync.Mutex
	tools         []mcp.Tool
	callToolFn    func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
	initDelay     time.Duration
	listDelay     time.Duration
	started       bool
	initialized   bool
	closed        bool
	startErr      error
	initializeErr error
	listToolsErr  error
}

func (m *mockTransport) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	return nil
}

func (m *mockTransport) Initialize(ctx context.Context, req mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	if m.initDelay > 0 {
		select {
		case <-time.After(m.initDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.initializeErr != nil {
		return nil, m.initializeErr
	}
	m.mu.Lock()
	m.initialized = true
	m.mu.Unlock()
	return &mcp.InitializeResult{}, nil
}

func (m *mockTransport) ListTools(ctx context.Context, req mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	if m.listDelay > 0 {
		select {
		case <-time.After(m.listDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.listToolsErr != nil {
		return nil, m.listToolsErr
	}
	return &mcp.ListToolsResult{Tools: m.tools}, nil
}

func (m *mockTransport) CallTool(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if m.callToolFn != nil {
		return m.callToolFn(ctx, req)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent("ok")},
	}, nil
}

func (m *mockTransport) ListPrompts(ctx context.Context, req mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error) {
	return &mcp.ListPromptsResult{}, nil
}

func (m *mockTransport) GetPrompt(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{}, nil
}

func (m *mockTransport) ListResources(ctx context.Context, req mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error) {
	return &mcp.ListResourcesResult{}, nil
}

func (m *mockTransport) ReadResource(ctx context.Context, req mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{}, nil
}

func (m *mockTransport) ListResourceTemplates(ctx context.Context, req mcp.ListResourceTemplatesRequest) (*mcp.ListResourceTemplatesResult, error) {
	return &mcp.ListResourceTemplatesResult{}, nil
}

func (m *mockTransport) Ping(ctx context.Context) error { return nil }

func (m *mockTransport) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

func (m *mockTransport) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// newTestServer creates a Server for testing with mock transports.
func newTestServer(t *testing.T, backends map[string]*mockTransport) *Server {
	t.Helper()

	backendConfigs := make(map[string]*config.MCPClientConfig, len(backends))
	for name := range backends {
		backendConfigs[name] = &config.MCPClientConfig{
			TransportType: config.MCPClientTypeSSE,
			URL:           "http://localhost/" + name,
		}
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		for name, mock := range backends {
			if conf.URL == "http://localhost/"+name {
				return mock, nil
			}
		}
		return nil, fmt.Errorf("unknown backend")
	}

	getUserToken := func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
		return "", nil
	}

	srv := NewServer(
		"test-aggregate",
		config.MCPClientTypeSSE,
		backendConfigs,
		&config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		getUserToken,
		factory,
		"http://localhost:8080",
	)
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
	})
	return srv
}

func TestDiscoverTools(t *testing.T) {
	pgTools := []mcp.Tool{
		{Name: "query", Description: "Run SQL query"},
		{Name: "tables", Description: "List tables"},
	}
	linearTools := []mcp.Tool{
		{Name: "create_issue", Description: "Create issue"},
	}

	backends := map[string]*mockTransport{
		"postgres": {tools: pgTools},
		"linear":   {tools: linearTools},
	}

	srv := newTestServer(t, backends)

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)

	totalTools := 0
	for _, bt := range tools {
		totalTools += len(bt)
	}
	assert.Equal(t, 3, totalTools)
	assert.Len(t, tools["postgres"], 2)
	assert.Len(t, tools["linear"], 1)
	assert.Equal(t, "Run SQL query", tools["postgres"][0].Description)
}

func TestDiscoverToolsCaching(t *testing.T) {
	var callCount atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	mock := &mockTransport{tools: []mcp.Tool{{Name: "query"}}}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		callCount.Add(1)
		return mock, nil
	}

	srv := NewServer(
		"test-aggregate",
		config.MCPClientTypeSSE,
		backendConfigs,
		&config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		factory,
		"http://localhost:8080",
	)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load())

	_, err = srv.getTools(context.Background(), "other@test.com")
	require.NoError(t, err)
	// Second call uses cache — no new transport created
	assert.Equal(t, int32(1), callCount.Load())
}

func TestDiscoverToolsTimeout(t *testing.T) {
	backends := map[string]*mockTransport{
		"fast": {tools: []mcp.Tool{{Name: "fast_tool"}}},
		"slow": {tools: []mcp.Tool{{Name: "slow_tool"}}, initDelay: 10 * time.Second},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"fast": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/fast"},
		"slow": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/slow"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		for name, mock := range backends {
			if conf.URL == "http://localhost/"+name {
				return mock, nil
			}
		}
		return nil, fmt.Errorf("unknown backend")
	}

	srv := NewServer(
		"test-aggregate",
		config.MCPClientTypeSSE,
		backendConfigs,
		&config.DiscoveryConfig{Timeout: 100 * time.Millisecond, CacheTTL: 60 * time.Second},
		func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		factory,
		"http://localhost:8080",
	)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Contains(t, tools, "fast")
	assert.NotContains(t, tools, "slow")
}

func TestToolRouting(t *testing.T) {
	var calledWithName string
	pgMock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
		callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			calledWithName = req.Params.Name
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.NewTextContent("result")},
			}, nil
		},
	}

	backends := map[string]*mockTransport{
		"postgres": pgMock,
	}

	srv := newTestServer(t, backends)

	handler := srv.makeToolHandler("user@test.com", "postgres")
	result, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "postgres.query",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "query", calledWithName)
	assert.Len(t, result.Content, 1)
}

func TestPerUserConnectionIsolation(t *testing.T) {
	var connCount atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		connCount.Add(1)
		return &mockTransport{
			tools: []mcp.Tool{{Name: "query"}},
		}, nil
	}

	srv := NewServer(
		"test-aggregate",
		config.MCPClientTypeSSE,
		backendConfigs,
		&config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		factory,
		"http://localhost:8080",
	)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	conn1, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "postgres")
	require.NoError(t, err)

	conn2, err := srv.getOrCreateConn(context.Background(), "bob@test.com", "postgres")
	require.NoError(t, err)

	assert.NotSame(t, conn1, conn2)
	assert.Equal(t, int32(2), connCount.Load())
}

func TestConnectionReuse(t *testing.T) {
	var connCount atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		connCount.Add(1)
		return &mockTransport{
			tools: []mcp.Tool{{Name: "query"}},
		}, nil
	}

	srv := NewServer(
		"test-aggregate",
		config.MCPClientTypeSSE,
		backendConfigs,
		&config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		factory,
		"http://localhost:8080",
	)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	conn1, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "postgres")
	require.NoError(t, err)

	conn2, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "postgres")
	require.NoError(t, err)

	assert.Same(t, conn1, conn2)
	assert.Equal(t, int32(1), connCount.Load())
}

func TestShutdownClosesConnections(t *testing.T) {
	mock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return mock, nil
	}

	srv := NewServer(
		"test-aggregate",
		config.MCPClientTypeSSE,
		backendConfigs,
		&config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		factory,
		"http://localhost:8080",
	)

	_, err := srv.getOrCreateConn(context.Background(), "user@test.com", "postgres")
	require.NoError(t, err)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)

	assert.True(t, mock.isClosed())
}

func TestToolFilter(t *testing.T) {
	pgMock := &mockTransport{
		tools: []mcp.Tool{
			{Name: "query"},
			{Name: "dangerous_drop"},
			{Name: "tables"},
		},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {
			TransportType: config.MCPClientTypeSSE,
			URL:           "http://localhost/postgres",
			Options: &config.Options{
				ToolFilter: &config.ToolFilterConfig{
					Mode: config.ToolFilterModeBlock,
					List: []string{"dangerous_drop"},
				},
			},
		},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return pgMock, nil
	}

	srv := NewServer(
		"test-aggregate",
		config.MCPClientTypeSSE,
		backendConfigs,
		&config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		factory,
		"http://localhost:8080",
	)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)

	pgTools := tools["postgres"]
	names := make([]string, len(pgTools))
	for i, tool := range pgTools {
		names[i] = tool.Name
	}

	assert.Contains(t, names, "query")
	assert.Contains(t, names, "tables")
	assert.NotContains(t, names, "dangerous_drop")
}

func TestAllBackendsFail(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"broken": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/broken"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return nil, fmt.Errorf("connection refused")
	}

	srv := NewServer(
		"test-aggregate",
		config.MCPClientTypeSSE,
		backendConfigs,
		&config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		factory,
		"http://localhost:8080",
	)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all backends failed")
}
