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
// When Close() is called, all in-flight operations that select on closeCh
// will fail — matching real transport behavior where closing the underlying
// connection interrupts pending requests.
type mockTransport struct {
	mu            sync.Mutex
	tools         []mcp.Tool
	callToolFn    func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
	initDelay     time.Duration
	listDelay     time.Duration
	started       bool
	initialized   bool
	closed        bool
	closeCh       chan struct{}
	startErr      error
	initializeErr error
	listToolsErr  error
}

func newMockTransport(tools []mcp.Tool) *mockTransport {
	return &mockTransport{
		tools:   tools,
		closeCh: make(chan struct{}),
	}
}

func (m *mockTransport) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.mu.Lock()
	m.started = true
	if m.closeCh == nil {
		m.closeCh = make(chan struct{})
	}
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
	m.mu.Lock()
	tools := make([]mcp.Tool, len(m.tools))
	copy(tools, m.tools)
	m.mu.Unlock()
	return &mcp.ListToolsResult{Tools: tools}, nil
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

// slowInitTransport wraps mockTransport with a controllable Initialize delay
// for testing singleflight context propagation.
type slowInitTransport struct {
	*mockTransport
	initStarted chan struct{}
	initProceed chan struct{}
}

func (s *slowInitTransport) Initialize(ctx context.Context, req mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	select {
	case s.initStarted <- struct{}{}:
	default:
	}
	select {
	case <-s.initProceed:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.mockTransport.Initialize(ctx, req)
}

func (m *mockTransport) Close() error {
	m.mu.Lock()
	alreadyClosed := m.closed
	m.closed = true
	m.mu.Unlock()
	if !alreadyClosed && m.closeCh != nil {
		close(m.closeCh)
	}
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

	srv := NewServer(ServerConfig{
		Name:            "test-aggregate",
		TransportType:   config.MCPClientTypeSSE,
		Backends:        backendConfigs,
		Discovery:       &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken:    getUserToken,
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
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

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
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

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 100 * time.Millisecond, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
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

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
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

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
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

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()

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

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
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

func TestDiscoverySurvivesCallerCancellation(t *testing.T) {
	initStarted := make(chan struct{})
	initProceed := make(chan struct{})

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	var factoryCalls atomic.Int32
	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		factoryCalls.Add(1)
		return &slowInitTransport{
			mockTransport: &mockTransport{
				tools: []mcp.Tool{{Name: "query"}},
			},
			initStarted: initStarted,
			initProceed: initProceed,
		}, nil
	}

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	callerCtx, callerCancel := context.WithCancel(context.Background())

	type toolResult struct {
		tools map[string][]mcp.Tool
		err   error
	}
	caller1Done := make(chan toolResult, 1)
	caller2Done := make(chan toolResult, 1)

	go func() {
		tools, err := srv.getTools(callerCtx, "user1@test.com")
		caller1Done <- toolResult{tools, err}
	}()
	go func() {
		tools, err := srv.getTools(context.Background(), "user2@test.com")
		caller2Done <- toolResult{tools, err}
	}()

	<-initStarted
	callerCancel()
	close(initProceed)

	r1 := <-caller1Done
	r2 := <-caller2Done

	// Both should succeed — context.WithoutCancel prevents caller1's
	// cancellation from killing the shared singleflight discovery.
	require.NoError(t, r2.err, "caller2 with Background context should succeed")
	assert.Len(t, r2.tools["postgres"], 1)

	// caller1 also succeeds because WithoutCancel detaches cancellation
	require.NoError(t, r1.err, "caller1 should also succeed (singleflight shares result)")
	assert.Len(t, r1.tools["postgres"], 1)

	// Only one transport should have been created (singleflight dedup)
	assert.Equal(t, int32(1), factoryCalls.Load())
}

func TestConcurrentGetOrCreateConn(t *testing.T) {
	var factoryCalls atomic.Int32

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		factoryCalls.Add(1)
		return &mockTransport{
			tools: []mcp.Tool{{Name: "query"}},
		}, nil
	}

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	const goroutines = 10
	var wg sync.WaitGroup
	conns := make([]*conn, goroutines)
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			conns[i], errs[i] = srv.getOrCreateConn(context.Background(), "alice@test.com", "postgres")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
	}
	for i := 1; i < goroutines; i++ {
		assert.Same(t, conns[0], conns[i], "all goroutines should get the same conn")
	}
	assert.Equal(t, int32(1), factoryCalls.Load(), "singleflight should create exactly one transport")
}

func TestDoubleShutdown(t *testing.T) {
	backends := map[string]*mockTransport{
		"postgres": {tools: []mcp.Tool{{Name: "query"}}},
	}
	srv := newTestServer(t, backends)

	err := srv.Shutdown(context.Background())
	require.NoError(t, err)

	// Second shutdown must not panic
	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestAllBackendsFail(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"broken": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/broken"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return nil, fmt.Errorf("connection refused")
	}

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getTools(context.Background(), "user@test.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all backends failed")
}

func TestEvictConnOnListToolsFailure(t *testing.T) {
	var factoryCalls atomic.Int32
	var failOnList atomic.Bool
	failOnList.Store(true)

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		factoryCalls.Add(1)
		mock := &mockTransport{
			tools: []mcp.Tool{{Name: "query"}},
		}
		if failOnList.Load() {
			mock.listToolsErr = fmt.Errorf("connection reset")
		}
		return mock, nil
	}

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// First discovery: ListTools fails, connection should be evicted
	_, err := srv.getTools(context.Background(), "user@test.com")
	require.Error(t, err)
	assert.Equal(t, int32(1), factoryCalls.Load())

	// Verify connection was evicted from the pool
	srv.connMu.RLock()
	_, exists := srv.conns[connKey{userEmail: "user@test.com", backendName: "postgres"}]
	srv.connMu.RUnlock()
	assert.False(t, exists, "broken connection should have been evicted")

	// Fix the backend and retry — should create a new connection
	failOnList.Store(false)
	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Equal(t, int32(2), factoryCalls.Load(), "should have created a fresh connection")
	assert.Len(t, tools["postgres"], 1)
}

func TestEvictConnOnCallToolFailure(t *testing.T) {
	var callCount atomic.Int32
	pgMock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
		callToolFn: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			n := callCount.Add(1)
			if n == 1 {
				return nil, fmt.Errorf("connection reset")
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{mcp.NewTextContent("ok")},
			}, nil
		},
	}

	backends := map[string]*mockTransport{
		"postgres": pgMock,
	}
	srv := newTestServer(t, backends)

	handler := srv.makeToolHandler("user@test.com", "postgres")

	// First call fails with transport error — connection should be evicted
	_, err := handler(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "postgres.query"},
	})
	require.Error(t, err)

	// Verify eviction happened
	srv.connMu.RLock()
	_, exists := srv.conns[connKey{userEmail: "user@test.com", backendName: "postgres"}]
	srv.connMu.RUnlock()
	assert.False(t, exists, "broken connection should have been evicted")
}

func TestGetUserTokenFailureDegradation(t *testing.T) {
	mock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {
			TransportType:     config.MCPClientTypeSSE,
			URL:               "http://localhost/postgres",
			RequiresUserToken: true,
		},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return mock, nil
	}

	var tokenCallCount atomic.Int32
	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			tokenCallCount.Add(1)
			return "", fmt.Errorf("token store unavailable")
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// Connection should succeed despite token failure — createConn logs
	// the warning and proceeds without the token.
	c, err := srv.getOrCreateConn(context.Background(), "user@test.com", "postgres")
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, int32(1), tokenCallCount.Load())

	// The connection should be functional
	assert.True(t, mock.started)
}

func TestShutdownDuringActiveToolCall(t *testing.T) {
	toolStarted := make(chan struct{})

	pgMock := newMockTransport([]mcp.Tool{{Name: "query"}})
	pgMock.callToolFn = func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		close(toolStarted)
		// Block until the transport is closed (simulating real behavior where
		// closing the underlying HTTP connection interrupts in-flight requests)
		// or the caller context is done.
		select {
		case <-pgMock.closeCh:
			return nil, fmt.Errorf("transport closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return pgMock, nil
	}

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()

	// Establish connection first
	_, err := srv.getOrCreateConn(context.Background(), "user@test.com", "postgres")
	require.NoError(t, err)

	// Start a tool call that blocks
	handler := srv.makeToolHandler("user@test.com", "postgres")
	type callResult struct {
		result *mcp.CallToolResult
		err    error
	}
	done := make(chan callResult, 1)
	go func() {
		r, err := handler(context.Background(), mcp.CallToolRequest{
			Params: mcp.CallToolParams{Name: "postgres.query"},
		})
		done <- callResult{r, err}
	}()

	// Wait for tool call to be in-flight
	<-toolStarted

	// Shutdown while tool call is active — Close() on the transport
	// closes closeCh, which unblocks the in-flight CallTool.
	shutdownErr := srv.Shutdown(context.Background())
	require.NoError(t, shutdownErr)

	// The in-flight tool call should complete with an error
	result := <-done
	assert.Error(t, result.err, "in-flight tool call should fail after shutdown")
}

func TestCacheExpiryAndRediscovery(t *testing.T) {
	mock := &mockTransport{
		tools: []mcp.Tool{{Name: "query"}},
	}

	backendConfigs := map[string]*config.MCPClientConfig{
		"postgres": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/postgres"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return mock, nil
	}

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 50 * time.Millisecond},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// First discovery
	tools, err := srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Len(t, tools["postgres"], 1)
	assert.Equal(t, "query", tools["postgres"][0].Name)

	// Simulate backend adding a new tool — mutate the mock directly so the
	// existing connection (reused on rediscovery) returns updated tools.
	mock.mu.Lock()
	mock.tools = []mcp.Tool{
		{Name: "query"},
		{Name: "tables"},
	}
	mock.mu.Unlock()

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Rediscovery should pick up the new tool
	tools, err = srv.getTools(context.Background(), "user@test.com")
	require.NoError(t, err)
	assert.Len(t, tools["postgres"], 2)
}

func TestMaxConnsPerUser(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"backend1": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/backend1"},
		"backend2": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/backend2"},
		"backend3": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/backend3"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return &mockTransport{tools: []mcp.Tool{{Name: "tool"}}}, nil
	}

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second, MaxConnsPerUser: 2},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	_, err := srv.getOrCreateConn(context.Background(), "alice@test.com", "backend1")
	require.NoError(t, err)
	_, err = srv.getOrCreateConn(context.Background(), "alice@test.com", "backend2")
	require.NoError(t, err)

	// Third connection exceeds limit
	_, err = srv.getOrCreateConn(context.Background(), "alice@test.com", "backend3")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserConnLimitExceeded)

	// Different user is unaffected
	_, err = srv.getOrCreateConn(context.Background(), "bob@test.com", "backend1")
	require.NoError(t, err)
}

func TestMaxConnsPerUserZeroUnlimited(t *testing.T) {
	backendConfigs := map[string]*config.MCPClientConfig{
		"b1": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/b1"},
		"b2": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/b2"},
		"b3": {TransportType: config.MCPClientTypeSSE, URL: "http://localhost/b3"},
	}

	factory := func(conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
		return &mockTransport{tools: []mcp.Tool{{Name: "tool"}}}, nil
	}

	srv := NewServer(ServerConfig{
		Name:          "test-aggregate",
		TransportType: config.MCPClientTypeSSE,
		Backends:      backendConfigs,
		Discovery:     &config.DiscoveryConfig{Timeout: 5 * time.Second, CacheTTL: 60 * time.Second, MaxConnsPerUser: 0},
		GetUserToken: func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
			return "", nil
		},
		CreateTransport: factory,
		BaseURL:         "http://localhost:8080",
	})
	srv.Start()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	for _, name := range []string{"b1", "b2", "b3"} {
		_, err := srv.getOrCreateConn(context.Background(), "alice@test.com", name)
		require.NoError(t, err, "connection to %s should succeed with unlimited pool", name)
	}
}
