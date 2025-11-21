package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/jsonrpc"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/servicecontext"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// SessionManager defines the interface for managing stdio sessions
type SessionManager interface {
	GetSession(key client.SessionKey) (*client.StdioSession, bool)
	GetOrCreateSession(ctx context.Context, key client.SessionKey, config *config.MCPClientConfig, info mcp.Implementation, setupBaseURL string, userToken string) (*client.StdioSession, error)
	RemoveSession(key client.SessionKey)
	Shutdown()
}

// UserTokenFunc defines a function that retrieves a formatted user token for a service
type UserTokenFunc func(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error)

// MCPHandler handles MCP requests with session management for stdio servers
type MCPHandler struct {
	serverName      string
	serverConfig    *config.MCPClientConfig
	storage         storage.Storage
	setupBaseURL    string
	info            mcp.Implementation
	sessionManager  SessionManager
	sharedSSEServer *server.SSEServer // Shared SSE server for stdio servers
	sharedMCPServer *server.MCPServer // Shared MCP server for stdio servers
	getUserToken    UserTokenFunc     // Function to get formatted user tokens
}

// NewMCPHandler creates a new MCP handler with session management
func NewMCPHandler(
	serverName string,
	serverConfig *config.MCPClientConfig,
	storage storage.Storage,
	setupBaseURL string,
	info mcp.Implementation,
	sessionManager SessionManager,
	sharedSSEServer *server.SSEServer, // Shared SSE server for stdio servers
	sharedMCPServer *server.MCPServer, // Shared MCP server for stdio servers
	getUserToken UserTokenFunc,
) *MCPHandler {
	return &MCPHandler{
		serverName:      serverName,
		serverConfig:    serverConfig,
		storage:         storage,
		setupBaseURL:    setupBaseURL,
		info:            info,
		sessionManager:  sessionManager,
		sharedSSEServer: sharedSSEServer,
		sharedMCPServer: sharedMCPServer,
		getUserToken:    getUserToken,
	}
}

func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get user from context - could be OAuth email or basic auth username
	userEmail, _ := oauth.GetUserFromContext(ctx)
	if userEmail == "" {
		// Check for basic auth username
		username, _ := servicecontext.GetUser(ctx)
		userEmail = username
	}

	// Get user token if available for applying to config
	// Don't block connection if missing - will check at tool invocation
	var userToken string
	if h.serverConfig.RequiresUserToken && userEmail != "" {
		userToken, _ = h.getUserTokenIfAvailable(ctx, userEmail)
	}

	// Apply user token to config if available
	serverConfig := h.serverConfig
	if userToken != "" {
		serverConfig = serverConfig.ApplyUserToken(userToken)
	}

	if serverConfig.TransportType == config.MCPClientTypeStreamable {
		switch r.Method {
		case http.MethodPost:
			log.LogInfoWithFields("mcp", "Handling streamable POST request", map[string]any{
				"path":          r.URL.Path,
				"server":        h.serverName,
				"user":          userEmail,
				"remoteAddr":    r.RemoteAddr,
				"contentLength": r.ContentLength,
			})
			h.handleStreamablePost(ctx, w, r, userEmail, serverConfig)
		case http.MethodGet:
			log.LogInfoWithFields("mcp", "Handling streamable GET request", map[string]any{
				"path":       r.URL.Path,
				"server":     h.serverName,
				"user":       userEmail,
				"remoteAddr": r.RemoteAddr,
				"userAgent":  r.UserAgent(),
			})
			h.handleStreamableGet(ctx, w, r, userEmail, serverConfig)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	} else {
		if h.isMessageRequest(r) {
			log.LogInfoWithFields("mcp", "Handling message request", map[string]any{
				"path":          r.URL.Path,
				"server":        h.serverName,
				"isStdio":       isStdioServer(serverConfig),
				"user":          userEmail,
				"remoteAddr":    r.RemoteAddr,
				"contentLength": r.ContentLength,
				"query":         r.URL.RawQuery,
			})
			h.handleMessageRequest(ctx, w, r, userEmail, serverConfig)
		} else {
			log.LogInfoWithFields("mcp", "Handling SSE request", map[string]any{
				"path":       r.URL.Path,
				"server":     h.serverName,
				"isStdio":    isStdioServer(serverConfig),
				"user":       userEmail,
				"remoteAddr": r.RemoteAddr,
				"userAgent":  r.UserAgent(),
			})
			h.handleSSERequest(ctx, w, r, userEmail, serverConfig)
		}
	}
}

// isMessageRequest checks if this is a message endpoint request
func (h *MCPHandler) isMessageRequest(r *http.Request) bool {
	// Check if path ends with /message or contains /message?
	path := r.URL.Path
	return strings.HasSuffix(path, "/message") || strings.Contains(path, "/message?")
}

// trackUserAccess tracks user access if user email is provided
func (h *MCPHandler) trackUserAccess(ctx context.Context, userEmail string) {
	if userEmail != "" {
		if h.storage != nil {
			if err := h.storage.UpsertUser(ctx, userEmail); err != nil {
				log.LogWarnWithFields("mcp", "Failed to track user", map[string]any{
					"error": err.Error(),
					"user":  userEmail,
				})
			}
		}
	}
}

// handleSSERequest handles SSE connection requests for stdio servers
func (h *MCPHandler) handleSSERequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	h.trackUserAccess(ctx, userEmail)

	if !isStdioServer(config) {
		// For non-stdio servers, handle normally
		h.handleNonStdioSSERequest(ctx, w, r, userEmail, config)
		return
	}

	// For stdio servers, use the shared SSE server
	if h.sharedSSEServer == nil {
		log.LogErrorWithFields("mcp", "No shared SSE server configured for stdio server", map[string]any{
			"server": h.serverName,
		})
		jsonwriter.WriteInternalServerError(w, "server misconfiguration")
		return
	}

	// The shared MCP server already has hooks configured in handler.go
	// that will be called when sessions are registered/unregistered
	// We need to set up our session-specific handlers
	// Create a custom hook handler for this specific request
	sessionHandler := NewSessionRequestHandler(h, userEmail, config, h.sharedMCPServer)

	// Store the handler in context so hooks can access it
	ctx = context.WithValue(ctx, SessionHandlerKey{}, sessionHandler)
	r = r.WithContext(ctx)
	log.LogInfoWithFields("mcp", "Serving SSE request for stdio server", map[string]any{
		"server": h.serverName,
		"user":   userEmail,
		"path":   r.URL.Path,
	})

	// Use the shared SSE server directly
	h.sharedSSEServer.ServeHTTP(w, r)
}

// handleMessageRequest handles message endpoint requests
func (h *MCPHandler) handleMessageRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	h.trackUserAccess(ctx, userEmail)

	if isStdioServer(config) {
		sessionID := r.URL.Query().Get("sessionId")
		if sessionID == "" {
			jsonrpc.WriteError(w, nil, jsonrpc.InvalidParams, "missing sessionId")
			return
		}

		key := client.SessionKey{
			UserEmail:  userEmail,
			ServerName: h.serverName,
			SessionID:  sessionID,
		}

		log.LogDebugWithFields("mcp", "Looking up stdio session", map[string]any{
			"sessionID": sessionID,
			"server":    h.serverName,
			"user":      userEmail,
		})

		_, ok := h.sessionManager.GetSession(key)
		if !ok {
			log.LogWarnWithFields("mcp", "Session not found - returning 404 with JSON-RPC error per MCP spec", map[string]any{
				"sessionID": sessionID,
				"server":    h.serverName,
				"user":      userEmail,
			})
			// Per MCP spec: return HTTP 404 Not Found when session is terminated or not found
			// The response body MAY comprise a JSON-RPC error response
			jsonrpc.WriteErrorWithStatus(w, nil, jsonrpc.InvalidParams, "session not found", http.StatusNotFound)
			return
		}
		if h.sharedSSEServer == nil {
			log.LogErrorWithFields("mcp", "No shared SSE server configured", map[string]any{
				"sessionID": sessionID,
			})
			jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "server misconfiguration")
			return
		}

		log.LogDebugWithFields("mcp", "Forwarding message request to shared SSE server", map[string]any{
			"sessionID": sessionID,
			"server":    h.serverName,
			"user":      userEmail,
		})

		h.sharedSSEServer.ServeHTTP(w, r)
		return
	}

	h.forwardMessageToBackend(ctx, w, r, config)
}

// handleNonStdioSSERequest handles SSE requests for non-stdio (native SSE) servers
func (h *MCPHandler) handleNonStdioSSERequest(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	log.LogInfoWithFields("mcp", "Proxying SSE request to backend", map[string]any{
		"service": h.serverName,
		"user":    userEmail,
		"backend": config.URL,
	})

	// Forward the SSE request directly to the backend
	forwardSSEToBackend(ctx, w, r, config)
}

// getUserTokenIfAvailable gets the user token if available, but doesn't send error responses
func (h *MCPHandler) getUserTokenIfAvailable(ctx context.Context, userEmail string) (string, error) {
	if userEmail == "" {
		return "", fmt.Errorf("authentication required")
	}

	log.LogTraceWithFields("mcp_handler", "Attempting to resolve user token", map[string]any{
		"server_name": h.serverName,
		"user":        userEmail,
	})

	// Check for service auth first - services provide their own user tokens
	if serviceAuth, ok := servicecontext.GetAuthInfo(ctx); ok {
		if serviceAuth.UserToken != "" {
			log.LogTraceWithFields("mcp_handler", "Found user token in service auth context", map[string]any{
				"server_name": h.serverName,
				"user":        userEmail,
			})
			return serviceAuth.UserToken, nil
		}
	}

	log.LogTraceWithFields("mcp_handler", "No user token in service auth context, falling back to storage lookup", map[string]any{
		"server_name": h.serverName,
		"user":        userEmail,
	})

	// Fall back to OAuth user token lookup in storage
	if h.storage == nil {
		return "", fmt.Errorf("storage not configured")
	}

	storedToken, err := h.storage.GetUserToken(ctx, userEmail, h.serverName)
	if err != nil {
		return "", err
	}

	// Use injected function to get formatted token with refresh handling
	if h.getUserToken != nil {
		return h.getUserToken(ctx, userEmail, h.serverName, h.serverConfig)
	}

	// Fallback: extract raw token without refresh (for backwards compatibility)
	var tokenString string
	switch storedToken.Type {
	case storage.TokenTypeManual:
		tokenString = storedToken.Value
	case storage.TokenTypeOAuth:
		if storedToken.OAuthData != nil {
			tokenString = storedToken.OAuthData.AccessToken
		}
	}

	return tokenString, nil
}

func (h *MCPHandler) forwardMessageToBackend(ctx context.Context, w http.ResponseWriter, r *http.Request, config *config.MCPClientConfig) {
	backendURL := strings.TrimSuffix(config.URL, "/sse") + "/message"
	if r.URL.RawQuery != "" {
		backendURL += "?" + r.URL.RawQuery
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.LogErrorWithFields("mcp", "Failed to read request body", map[string]any{
			"error":  err.Error(),
			"server": h.serverName,
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "failed to read request")
		return
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, backendURL, bytes.NewReader(body))
	if err != nil {
		log.LogErrorWithFields("mcp", "Failed to create backend request", map[string]any{
			"error":  err.Error(),
			"server": h.serverName,
			"url":    backendURL,
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "failed to create request")
		return
	}

	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	log.LogDebugWithFields("mcp", "Forwarding message to backend", map[string]any{
		"server":     h.serverName,
		"backendURL": backendURL,
		"method":     r.Method,
		"headers":    config.Headers,
	})

	client := &http.Client{
		Timeout: config.Timeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.LogErrorWithFields("mcp", "Backend request failed", map[string]any{
			"error":  err.Error(),
			"server": h.serverName,
			"url":    backendURL,
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "backend request failed")
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)

	maps.Copy(w.Header(), resp.Header)

	if _, err := io.Copy(w, resp.Body); err != nil {
		log.LogErrorWithFields("mcp", "Failed to copy response body", map[string]any{
			"error":  err.Error(),
			"server": h.serverName,
		})
	}
}

// handleStreamablePost handles POST requests for streamable-http transport
func (h *MCPHandler) handleStreamablePost(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	h.trackUserAccess(ctx, userEmail)

	log.LogInfoWithFields("mcp", "Proxying streamable POST request to backend", map[string]any{
		"service": h.serverName,
		"user":    userEmail,
		"backend": config.URL,
	})

	forwardStreamablePostToBackend(ctx, w, r, config)
}

// handleStreamableGet handles GET requests for streamable-http transport
func (h *MCPHandler) handleStreamableGet(ctx context.Context, w http.ResponseWriter, r *http.Request, userEmail string, config *config.MCPClientConfig) {
	h.trackUserAccess(ctx, userEmail)

	acceptHeader := r.Header.Get("Accept")
	if !strings.Contains(acceptHeader, "text/event-stream") {
		http.Error(w, "GET requests must accept text/event-stream", http.StatusNotAcceptable)
		return
	}

	log.LogInfoWithFields("mcp", "Proxying streamable GET request to backend", map[string]any{
		"service": h.serverName,
		"user":    userEmail,
		"backend": config.URL,
	})

	forwardSSEToBackend(ctx, w, r, config)
}
