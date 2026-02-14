package server

import (
	"context"
	"time"

	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// SessionHandlerKey is the context key for session handlers
type SessionHandlerKey struct{}

// SessionRequestHandler handles session-specific logic for a request
type SessionRequestHandler struct {
	h         *MCPHandler
	userEmail string
	config    *config.MCPClientConfig
	mcpServer *mcpserver.MCPServer // The shared MCP server
}

// NewSessionRequestHandler creates a new session request handler with all dependencies
func NewSessionRequestHandler(h *MCPHandler, userEmail string, config *config.MCPClientConfig, mcpServer *mcpserver.MCPServer) *SessionRequestHandler {
	return &SessionRequestHandler{
		h:         h,
		userEmail: userEmail,
		config:    config,
		mcpServer: mcpServer,
	}
}

// GetUserEmail returns the user email for this session
func (s *SessionRequestHandler) GetUserEmail() string {
	return s.userEmail
}

// GetServerName returns the server name for this session
func (s *SessionRequestHandler) GetServerName() string {
	return s.h.serverName
}

// GetStorage returns the storage interface
func (s *SessionRequestHandler) GetStorage() storage.Storage {
	return s.h.storage
}

// HandleSessionRegistration handles the registration of a new session
func HandleSessionRegistration(
	sessionCtx context.Context,
	session mcpserver.ClientSession,
	handler *SessionRequestHandler,
	sessionManager *client.StdioSessionManager,
) {
	// Create stdio process for this session
	key := client.SessionKey{
		UserEmail:  handler.userEmail,
		ServerName: handler.h.serverName,
		SessionID:  session.SessionID(),
	}

	log.LogDebugWithFields("server", "Registering session", map[string]any{
		"sessionID": session.SessionID(),
		"server":    handler.h.serverName,
		"user":      handler.userEmail,
	})

	log.LogTraceWithFields("server", "Session registration started", map[string]any{
		"sessionID":         session.SessionID(),
		"server":            handler.h.serverName,
		"user":              handler.userEmail,
		"requiresUserToken": handler.config.RequiresUserToken,
		"transportType":     handler.config.TransportType,
		"command":           handler.config.Command,
	})

	var userToken string
	if handler.config.RequiresUserToken && handler.userEmail != "" {
		token, err := handler.h.getUserToken(sessionCtx, handler.userEmail, handler.h.serverName, handler.config)
		if err != nil {
			log.LogDebugWithFields("server", "No user token found", map[string]any{
				"server": handler.h.serverName,
				"user":   handler.userEmail,
			})
		} else {
			userToken = token
		}
	}

	stdioSession, err := sessionManager.GetOrCreateSession(
		sessionCtx,
		key,
		handler.config,
		handler.h.info,
		handler.h.setupBaseURL,
		userToken,
	)
	if err != nil {
		log.LogErrorWithFields("server", "Failed to create stdio session", map[string]any{
			"error":     err.Error(),
			"sessionID": session.SessionID(),
			"server":    handler.h.serverName,
			"user":      handler.userEmail,
		})
		return
	}

	// Discover and register capabilities from the stdio process
	if err := stdioSession.DiscoverAndRegisterCapabilities(
		sessionCtx,
		handler.mcpServer,
		handler.userEmail,
		handler.config.RequiresUserToken,
		handler.h.storage,
		handler.h.serverName,
		handler.h.setupBaseURL,
		handler.config.UserAuthentication,
		session,
	); err != nil {
		log.LogErrorWithFields("server", "Failed to discover and register capabilities", map[string]any{
			"error":     err.Error(),
			"sessionID": session.SessionID(),
			"server":    handler.h.serverName,
			"user":      handler.userEmail,
		})
		if err := sessionManager.RemoveSession(key); err != nil {
			log.LogErrorWithFields("server", "Failed to remove session on capability failure", map[string]any{
				"sessionID": session.SessionID(),
				"server":    handler.h.serverName,
				"user":      handler.userEmail,
				"error":     err.Error(),
			})
		}
		return
	}

	if handler.userEmail != "" {
		if handler.h.storage != nil {
			activeSession := storage.ActiveSession{
				SessionID:  session.SessionID(),
				UserEmail:  handler.userEmail,
				ServerName: handler.h.serverName,
				Created:    time.Now(),
				LastActive: time.Now(),
			}
			if err := handler.h.storage.TrackSession(sessionCtx, activeSession); err != nil {
				log.LogWarnWithFields("server", "Failed to track session", map[string]any{
					"error":     err.Error(),
					"sessionID": session.SessionID(),
					"user":      handler.userEmail,
				})
			}
		}
	}

	log.LogInfoWithFields("server", "Session successfully created and connected", map[string]any{
		"sessionID": session.SessionID(),
		"server":    handler.h.serverName,
		"user":      handler.userEmail,
	})
}
