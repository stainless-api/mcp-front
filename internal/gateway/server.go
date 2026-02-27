package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	toolCacheTTL      = 60 * time.Second
	perBackendTimeout = 45 * time.Second
	discoveryDeadline = 10 * time.Second
)

type UserTokenFunc func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error)

type TransportCreator func(name string, conf *config.MCPClientConfig) (client.MCPClientInterface, error)

type Server struct {
	serverConfigs   map[string]*config.MCPClientConfig
	getUserToken    UserTokenFunc
	baseURL         string
	createTransport TransportCreator

	mu       sync.Mutex
	sessions map[string]*userSession
}

type userSession struct {
	cacheMu   sync.Mutex
	toolCache []cachedTool
	cacheExp  time.Time

	backendsMu sync.Mutex
	backends   map[string]*backendConn
}

type backendConn struct {
	client client.MCPClientInterface
}

type cachedTool struct {
	Tool        mcp.Tool
	ServiceName string
}

func NewServer(
	serverConfigs map[string]*config.MCPClientConfig,
	getUserToken UserTokenFunc,
	baseURL string,
) *Server {
	return newServer(serverConfigs, getUserToken, baseURL, defaultCreateTransport)
}

func newServer(
	serverConfigs map[string]*config.MCPClientConfig,
	getUserToken UserTokenFunc,
	baseURL string,
	createTransport TransportCreator,
) *Server {
	return &Server{
		serverConfigs:   serverConfigs,
		getUserToken:    getUserToken,
		baseURL:         baseURL,
		createTransport: createTransport,
		sessions:        make(map[string]*userSession),
	}
}

func defaultCreateTransport(_ string, conf *config.MCPClientConfig) (client.MCPClientInterface, error) {
	return client.DefaultTransportCreator(conf)
}

func (s *Server) HandleInitialize(_ string) map[string]any {
	return map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "gateway",
			"version": "1.0",
		},
	}
}

func (s *Server) PreWarm(userEmail string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err := s.HandleToolsList(ctx, userEmail); err != nil {
		log.LogWarnWithFields("gateway", "Pre-warm tool discovery failed", map[string]any{
			"user":  userEmail,
			"error": err.Error(),
		})
	}
}

func (s *Server) HandleToolsList(ctx context.Context, userEmail string) ([]map[string]any, error) {
	session := s.getOrCreateSession(userEmail)

	session.cacheMu.Lock()
	if time.Now().Before(session.cacheExp) && session.toolCache != nil {
		tools := formatTools(session.toolCache)
		session.cacheMu.Unlock()
		return tools, nil
	}
	session.cacheMu.Unlock()

	tools, err := s.discoverTools(ctx, userEmail, session)
	if err != nil {
		return nil, err
	}

	session.cacheMu.Lock()
	session.toolCache = tools
	session.cacheExp = time.Now().Add(toolCacheTTL)
	session.cacheMu.Unlock()

	return formatTools(tools), nil
}

func (s *Server) HandleToolCall(ctx context.Context, userEmail string, namespacedName string, args map[string]any) (*mcp.CallToolResult, error) {
	serviceName, toolName, err := ParseNamespacedTool(namespacedName)
	if err != nil {
		return nil, fmt.Errorf("invalid tool name: %w", err)
	}

	if _, ok := s.serverConfigs[serviceName]; !ok {
		return nil, fmt.Errorf("unknown service: %s", serviceName)
	}

	session := s.getOrCreateSession(userEmail)

	backend, err := s.getOrCreateBackend(ctx, userEmail, serviceName, session)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", serviceName, err)
	}

	req := mcp.CallToolRequest{}
	req.Params.Name = toolName
	req.Params.Arguments = args

	return backend.client.CallTool(ctx, req)
}

func (s *Server) Shutdown() {
	s.mu.Lock()
	sessions := make(map[string]*userSession, len(s.sessions))
	for k, v := range s.sessions {
		sessions[k] = v
	}
	s.sessions = make(map[string]*userSession)
	s.mu.Unlock()

	for _, session := range sessions {
		session.backendsMu.Lock()
		for name, backend := range session.backends {
			if err := backend.client.Close(); err != nil {
				log.LogErrorWithFields("gateway", "Failed to close backend", map[string]any{
					"service": name,
					"error":   err.Error(),
				})
			}
		}
		session.backendsMu.Unlock()
	}
}

func (s *Server) getOrCreateSession(userEmail string) *userSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[userEmail]
	if !ok {
		session = &userSession{
			backends: make(map[string]*backendConn),
		}
		s.sessions[userEmail] = session
	}
	return session
}

func (s *Server) discoverTools(ctx context.Context, userEmail string, session *userSession) ([]cachedTool, error) {
	type result struct {
		serviceName string
		tools       []mcp.Tool
		err         error
	}

	total := len(s.serverConfigs)
	results := make(chan result, total)

	for serviceName := range s.serverConfigs {
		go func(svcName string) {
			backendCtx, backendCancel := context.WithTimeout(ctx, perBackendTimeout)
			defer backendCancel()

			backend, err := s.getOrCreateBackend(backendCtx, userEmail, svcName, session)
			if err != nil {
				results <- result{serviceName: svcName, err: err}
				return
			}

			var allTools []mcp.Tool
			req := mcp.ListToolsRequest{}
			for {
				resp, err := backend.client.ListTools(backendCtx, req)
				if err != nil {
					results <- result{serviceName: svcName, err: err}
					return
				}
				allTools = append(allTools, resp.Tools...)
				if resp.NextCursor == "" {
					break
				}
				req.Params.Cursor = resp.NextCursor
			}

			results <- result{serviceName: svcName, tools: allTools}
		}(serviceName)
	}

	deadline := time.After(discoveryDeadline)
	var allCached []cachedTool
	received := 0

	for received < total {
		select {
		case r := <-results:
			received++
			if r.err != nil {
				log.LogWarnWithFields("gateway", "Failed to discover tools from backend", map[string]any{
					"service": r.serviceName,
					"error":   r.err.Error(),
				})
				continue
			}
			for _, tool := range r.tools {
				namespaced := tool
				namespaced.Name = NamespaceTool(r.serviceName, tool.Name)
				allCached = append(allCached, cachedTool{
					Tool:        namespaced,
					ServiceName: r.serviceName,
				})
			}
		case <-deadline:
			log.LogWarnWithFields("gateway", "Discovery deadline reached, returning partial results", map[string]any{
				"received": received,
				"total":    total,
				"user":     userEmail,
			})
			return allCached, nil
		}
	}

	return allCached, nil
}

func (s *Server) getOrCreateBackend(ctx context.Context, userEmail, serviceName string, session *userSession) (*backendConn, error) {
	session.backendsMu.Lock()
	if backend, ok := session.backends[serviceName]; ok {
		session.backendsMu.Unlock()
		return backend, nil
	}
	session.backendsMu.Unlock()

	serverConfig, ok := s.serverConfigs[serviceName]
	if !ok {
		return nil, fmt.Errorf("unknown service: %s", serviceName)
	}

	appliedConfig := serverConfig
	if serverConfig.RequiresUserToken && s.getUserToken != nil {
		token, err := s.getUserToken(ctx, userEmail, serviceName, serverConfig)
		if err != nil {
			return nil, fmt.Errorf("user token required for %s: %w", serviceName, err)
		}
		appliedConfig = serverConfig.ApplyUserToken(token)
	}

	mcpClient, err := s.createTransport(serviceName, appliedConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport for %s: %w", serviceName, err)
	}

	if err := mcpClient.Start(ctx); err != nil {
		mcpClient.Close()
		return nil, fmt.Errorf("failed to start client for %s: %w", serviceName, err)
	}

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "mcp-front-gateway",
		Version: "1.0",
	}

	if _, err := mcpClient.Initialize(ctx, initReq); err != nil {
		mcpClient.Close()
		return nil, fmt.Errorf("failed to initialize %s: %w", serviceName, err)
	}

	session.backendsMu.Lock()
	if existing, ok := session.backends[serviceName]; ok {
		session.backendsMu.Unlock()
		mcpClient.Close()
		return existing, nil
	}
	backend := &backendConn{client: mcpClient}
	session.backends[serviceName] = backend
	session.backendsMu.Unlock()

	log.LogInfoWithFields("gateway", "Connected to backend", map[string]any{
		"service": serviceName,
		"user":    userEmail,
	})

	return backend, nil
}

func formatTools(tools []cachedTool) []map[string]any {
	result := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		entry := map[string]any{
			"name": t.Tool.Name,
		}
		if t.Tool.Description != "" {
			entry["description"] = t.Tool.Description
		}
		if t.Tool.InputSchema.Type != "" {
			entry["inputSchema"] = t.Tool.InputSchema
		}
		result = append(result, entry)
	}
	return result
}
