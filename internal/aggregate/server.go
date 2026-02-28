package aggregate

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/servicecontext"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"golang.org/x/sync/singleflight"
)

const (
	connIdleTimeout     = 5 * time.Minute
	connCleanupInterval = 1 * time.Minute
)

// UserTokenFunc retrieves a user's token for a specific backend service.
type UserTokenFunc func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error)

// connKey identifies a per-user, per-backend connection.
type connKey struct {
	userEmail   string
	backendName string
}

func (k connKey) String() string { return k.userEmail + "\x00" + k.backendName }

// conn is a long-lived connection to one backend for one user.
type conn struct {
	client       client.MCPClientInterface
	cancel       context.CancelFunc
	ctx          context.Context
	lastAccessed atomic.Pointer[time.Time]
}

// cachedTools holds discovered tool schemas. Global, not per-user.
type cachedTools struct {
	tools   map[string][]mcp.Tool // backendName -> filtered tools
	expires time.Time
}

// mcpTransport is satisfied by both mcpserver.SSEServer and mcpserver.StreamableHTTPServer.
type mcpTransport interface {
	http.Handler
	Shutdown(context.Context) error
}

// Server aggregates multiple MCP backends into a single endpoint.
// Tools from backends are namespaced as "backend.toolName".
type Server struct {
	name            string
	backends        map[string]*config.MCPClientConfig
	discovery       *config.DiscoveryConfig
	getUserToken    UserTokenFunc
	createTransport client.TransportCreator
	baseURL         string

	cacheMu        sync.RWMutex
	cache          *cachedTools
	discoveryGroup singleflight.Group

	connMu    sync.RWMutex
	conns     map[connKey]*conn
	connGroup singleflight.Group

	mcpServer *mcpserver.MCPServer
	transport mcpTransport

	stopCleanup chan struct{}
	wg          sync.WaitGroup
}

func NewServer(
	name string,
	transportType config.MCPClientType,
	backends map[string]*config.MCPClientConfig,
	discovery *config.DiscoveryConfig,
	getUserToken UserTokenFunc,
	createTransport client.TransportCreator,
	baseURL string,
) *Server {
	s := &Server{
		name:            name,
		backends:        backends,
		discovery:       discovery,
		getUserToken:    getUserToken,
		createTransport: createTransport,
		baseURL:         baseURL,
		conns:           make(map[connKey]*conn),
		stopCleanup:     make(chan struct{}),
	}

	hooks := &mcpserver.Hooks{}
	hooks.AddOnRegisterSession(s.onRegisterSession)

	s.mcpServer = mcpserver.NewMCPServer(name, "1.0.0",
		mcpserver.WithHooks(hooks),
		mcpserver.WithToolCapabilities(true),
	)

	switch transportType {
	case config.MCPClientTypeStreamable:
		streamable := mcpserver.NewStreamableHTTPServer(s.mcpServer,
			mcpserver.WithEndpointPath("/"+name+"/"),
			mcpserver.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
				return r.Context()
			}),
		)
		s.transport = streamable
	default:
		sse := mcpserver.NewSSEServer(s.mcpServer,
			mcpserver.WithStaticBasePath(name),
			mcpserver.WithBaseURL(baseURL),
		)
		s.transport = sse
	}

	s.wg.Add(1)
	go s.cleanupLoop()

	return s
}

func (s *Server) Handler() http.Handler {
	return s.transport
}

func (s *Server) Shutdown(ctx context.Context) error {
	close(s.stopCleanup)
	s.wg.Wait()

	err := s.transport.Shutdown(ctx)

	s.connMu.Lock()
	snapshot := make(map[connKey]*conn, len(s.conns))
	maps.Copy(snapshot, s.conns)
	s.conns = nil
	s.connMu.Unlock()

	for key, c := range snapshot {
		c.cancel()
		if closeErr := c.client.Close(); closeErr != nil {
			log.LogWarnWithFields("aggregate", "Error closing backend connection", map[string]any{
				"server":  s.name,
				"backend": key.backendName,
				"user":    key.userEmail,
				"error":   closeErr.Error(),
			})
		}
	}

	return err
}

func (s *Server) onRegisterSession(ctx context.Context, session mcpserver.ClientSession) {
	userEmail, _ := oauth.GetUserFromContext(ctx)
	if userEmail == "" {
		userEmail, _ = servicecontext.GetUser(ctx)
	}
	if userEmail == "" {
		log.LogWarnWithFields("aggregate", "No user identity in session context", map[string]any{
			"server":    s.name,
			"sessionID": session.SessionID(),
		})
		return
	}

	tools, err := s.getTools(ctx, userEmail)
	if err != nil {
		log.LogErrorWithFields("aggregate", "Tool discovery failed", map[string]any{
			"server": s.name,
			"user":   userEmail,
			"error":  err.Error(),
		})
		return
	}

	sessionWithTools, ok := session.(mcpserver.SessionWithTools)
	if !ok {
		log.LogErrorWithFields("aggregate", "Session does not support per-session tools", map[string]any{
			"server":    s.name,
			"sessionID": session.SessionID(),
		})
		return
	}

	sessionTools := make(map[string]mcpserver.ServerTool)
	for backendName, backendTools := range tools {
		for _, tool := range backendTools {
			namespacedName := PrefixToolName(backendName, tool.Name)
			tool.Name = namespacedName
			sessionTools[namespacedName] = mcpserver.ServerTool{
				Tool:    tool,
				Handler: s.makeToolHandler(userEmail, backendName),
			}
		}
	}
	sessionWithTools.SetSessionTools(sessionTools)

	log.LogInfoWithFields("aggregate", "Session registered", map[string]any{
		"server":    s.name,
		"sessionID": session.SessionID(),
		"user":      userEmail,
		"toolCount": len(sessionTools),
	})
}

// getTools returns cached tool schemas or triggers fresh discovery.
// Uses singleflight to prevent concurrent discoveries (cache stampede).
func (s *Server) getTools(ctx context.Context, userEmail string) (map[string][]mcp.Tool, error) {
	s.cacheMu.RLock()
	if s.cache != nil && time.Now().Before(s.cache.expires) {
		tools := s.cache.tools
		s.cacheMu.RUnlock()
		return tools, nil
	}
	s.cacheMu.RUnlock()

	v, err, _ := s.discoveryGroup.Do("discover", func() (any, error) {
		// Double-check inside singleflight
		s.cacheMu.RLock()
		if s.cache != nil && time.Now().Before(s.cache.expires) {
			tools := s.cache.tools
			s.cacheMu.RUnlock()
			return tools, nil
		}
		s.cacheMu.RUnlock()

		return s.discoverAllTools(ctx, userEmail)
	})

	if err != nil {
		return nil, err
	}
	return v.(map[string][]mcp.Tool), nil
}

// discoverAllTools fans out to all backends in parallel.
func (s *Server) discoverAllTools(ctx context.Context, userEmail string) (map[string][]mcp.Tool, error) {
	discoveryCtx, cancel := context.WithTimeout(ctx, s.discovery.Timeout)
	defer cancel()

	type result struct {
		backendName string
		tools       []mcp.Tool
		err         error
	}

	ch := make(chan result, len(s.backends))

	for name, conf := range s.backends {
		go func(name string, conf *config.MCPClientConfig) {
			tools, err := s.discoverBackendTools(discoveryCtx, userEmail, name, conf)
			ch <- result{backendName: name, tools: tools, err: err}
		}(name, conf)
	}

	allTools := make(map[string][]mcp.Tool)
	var errors []string

	for range s.backends {
		r := <-ch
		if r.err != nil {
			log.LogWarnWithFields("aggregate", "Backend discovery failed", map[string]any{
				"server":  s.name,
				"backend": r.backendName,
				"error":   r.err.Error(),
			})
			errors = append(errors, fmt.Sprintf("%s: %v", r.backendName, r.err))
			continue
		}
		allTools[r.backendName] = r.tools
	}

	totalTools := 0
	for _, tools := range allTools {
		totalTools += len(tools)
	}

	if totalTools == 0 && len(errors) > 0 {
		return nil, fmt.Errorf("all backends failed discovery: %s", strings.Join(errors, "; "))
	}

	s.cacheMu.Lock()
	s.cache = &cachedTools{
		tools:   allTools,
		expires: time.Now().Add(s.discovery.CacheTTL),
	}
	s.cacheMu.Unlock()

	log.LogInfoWithFields("aggregate", "Tool discovery completed", map[string]any{
		"server":    s.name,
		"toolCount": totalTools,
		"errors":    len(errors),
	})

	return allTools, nil
}

// discoverBackendTools connects to a backend, lists its tools, and applies filtering.
func (s *Server) discoverBackendTools(ctx context.Context, userEmail, backendName string, conf *config.MCPClientConfig) ([]mcp.Tool, error) {
	c, err := s.getOrCreateConn(ctx, userEmail, backendName)
	if err != nil {
		return nil, err
	}

	var tools []mcp.Tool
	req := mcp.ListToolsRequest{}
	for {
		resp, err := c.client.ListTools(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("listing tools: %w", err)
		}
		tools = append(tools, resp.Tools...)
		if resp.NextCursor == "" {
			break
		}
		req.Params.Cursor = resp.NextCursor
	}

	filter := toolFilterFunc(conf)
	filtered := make([]mcp.Tool, 0, len(tools))
	for _, tool := range tools {
		if filter(tool.Name) {
			filtered = append(filtered, tool)
		}
	}

	return filtered, nil
}

func (s *Server) makeToolHandler(userEmail, backendName string) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		_, originalName, ok := ParseToolName(request.Params.Name)
		if !ok {
			return nil, fmt.Errorf("invalid namespaced tool name: %s", request.Params.Name)
		}

		c, err := s.getOrCreateConn(ctx, userEmail, backendName)
		if err != nil {
			return nil, fmt.Errorf("backend %s: %w", backendName, err)
		}

		now := time.Now()
		c.lastAccessed.Store(&now)

		request.Params.Name = originalName
		return c.client.CallTool(ctx, request)
	}
}

func (s *Server) getOrCreateConn(ctx context.Context, userEmail, backendName string) (*conn, error) {
	key := connKey{userEmail: userEmail, backendName: backendName}

	v, err, _ := s.connGroup.Do(key.String(), func() (any, error) {
		s.connMu.RLock()
		existing, ok := s.conns[key]
		s.connMu.RUnlock()

		if ok {
			now := time.Now()
			existing.lastAccessed.Store(&now)
			return existing, nil
		}

		return s.createConn(ctx, userEmail, backendName)
	})

	if err != nil {
		return nil, err
	}
	return v.(*conn), nil
}

func (s *Server) createConn(ctx context.Context, userEmail, backendName string) (*conn, error) {
	backendConfig := s.backends[backendName]

	effectiveConfig := backendConfig
	if backendConfig.RequiresUserToken && userEmail != "" && s.getUserToken != nil {
		token, err := s.getUserToken(ctx, userEmail, backendName, backendConfig)
		if err != nil {
			log.LogWarnWithFields("aggregate", "Failed to get user token", map[string]any{
				"server":  s.name,
				"backend": backendName,
				"user":    userEmail,
				"error":   err.Error(),
			})
		} else if token != "" {
			effectiveConfig = backendConfig.ApplyUserToken(token)
		}
	}

	transport, err := s.createTransport(effectiveConfig)
	if err != nil {
		return nil, fmt.Errorf("creating transport: %w", err)
	}

	connCtx, cancel := context.WithCancel(context.Background())

	if err := transport.Start(connCtx); err != nil {
		cancel()
		transport.Close()
		return nil, fmt.Errorf("starting: %w", err)
	}

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: s.name, Version: "1.0.0"}
	// Initialize is a request-response exchange: use the caller's context so
	// discovery timeouts propagate. Start uses connCtx because for SSE it
	// controls the persistent stream lifetime.
	if _, err := transport.Initialize(ctx, initReq); err != nil {
		cancel()
		transport.Close()
		return nil, fmt.Errorf("initializing: %w", err)
	}

	now := time.Now()
	c := &conn{
		client: transport,
		cancel: cancel,
		ctx:    connCtx,
	}
	c.lastAccessed.Store(&now)

	key := connKey{userEmail: userEmail, backendName: backendName}
	s.connMu.Lock()
	s.conns[key] = c
	s.connMu.Unlock()

	log.LogInfoWithFields("aggregate", "Backend connection established", map[string]any{
		"server":  s.name,
		"backend": backendName,
		"user":    userEmail,
	})

	return c, nil
}

func (s *Server) removeConn(key connKey) {
	s.connMu.Lock()
	c, ok := s.conns[key]
	if ok {
		delete(s.conns, key)
	}
	s.connMu.Unlock()

	if ok {
		c.cancel()
		c.client.Close()
	}
}

func (s *Server) cleanupLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(connCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.cleanupIdleConns()
		}
	}
}

func (s *Server) cleanupIdleConns() {
	now := time.Now()

	s.connMu.RLock()
	var idle []connKey
	for key, c := range s.conns {
		last := c.lastAccessed.Load()
		if last != nil && now.Sub(*last) > connIdleTimeout {
			idle = append(idle, key)
		}
	}
	s.connMu.RUnlock()

	for _, key := range idle {
		log.LogInfoWithFields("aggregate", "Closing idle connection", map[string]any{
			"server":  s.name,
			"backend": key.backendName,
			"user":    key.userEmail,
		})
		s.removeConn(key)
	}
}

// toolFilterFunc builds a filter predicate from a backend's config.
func toolFilterFunc(conf *config.MCPClientConfig) func(string) bool {
	if conf.Options == nil || conf.Options.ToolFilter == nil || len(conf.Options.ToolFilter.List) == 0 {
		return func(string) bool { return true }
	}

	filter := conf.Options.ToolFilter
	set := make(map[string]struct{}, len(filter.List))
	for _, name := range filter.List {
		set[name] = struct{}{}
	}

	switch config.ToolFilterMode(strings.ToLower(string(filter.Mode))) {
	case config.ToolFilterModeAllow:
		return func(name string) bool {
			_, ok := set[name]
			return ok
		}
	case config.ToolFilterModeBlock:
		return func(name string) bool {
			_, ok := set[name]
			return !ok
		}
	default:
		return func(string) bool { return true }
	}
}
