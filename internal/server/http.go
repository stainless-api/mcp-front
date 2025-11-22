package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// UserTokenService handles user token retrieval and OAuth refresh
type UserTokenService struct {
	storage            storage.Storage
	serviceOAuthClient *auth.ServiceOAuthClient
}

// NewUserTokenService creates a new user token service
func NewUserTokenService(storage storage.Storage, serviceOAuthClient *auth.ServiceOAuthClient) *UserTokenService {
	return &UserTokenService{
		storage:            storage,
		serviceOAuthClient: serviceOAuthClient,
	}
}

// GetUserToken retrieves and formats a user token for a service, handling OAuth refresh.
//
// Token refresh strategy: Optimistic continuation on failure.
// If refresh fails, we log a warning and continue with the current token. The external
// service will reject the expired token with 401, giving the user a clear error.
// This is acceptable because: (1) refresh failures are rare (network issues, revoked
// tokens), and (2) forcing users to re-auth is better than silently hiding auth issues.
func (uts *UserTokenService) GetUserToken(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
	storedToken, err := uts.storage.GetUserToken(ctx, userEmail, serviceName)
	if err != nil {
		return "", err
	}

	switch storedToken.Type {
	case storage.TokenTypeManual:
		// Token is already in storedToken.Value, formatUserToken will handle it
		break
	case storage.TokenTypeOAuth:
		if storedToken.OAuthData != nil && uts.serviceOAuthClient != nil {
			if err := uts.serviceOAuthClient.RefreshToken(ctx, userEmail, serviceName, serviceConfig); err != nil {
				log.LogWarnWithFields("user_token", "Failed to refresh OAuth token", map[string]any{
					"service": serviceName,
					"user":    userEmail,
					"error":   err.Error(),
				})
				// Continue with current token - the service will handle auth failure
			} else {
				// Re-fetch the updated token after refresh
				refreshedToken, err := uts.storage.GetUserToken(ctx, userEmail, serviceName)
				if err != nil {
					log.LogErrorWithFields("user_token", "Failed to fetch token after successful refresh", map[string]any{
						"service": serviceName,
						"user":    userEmail,
						"error":   err.Error(),
					})
					// Continue with original token - the service will handle auth failure
				} else {
					storedToken = refreshedToken
					var expiresAt time.Time
					if refreshedToken.OAuthData != nil {
						expiresAt = refreshedToken.OAuthData.ExpiresAt
					}
					log.LogInfoWithFields("user_token", "OAuth token refreshed and updated", map[string]any{
						"service":   serviceName,
						"user":      userEmail,
						"expiresAt": expiresAt,
					})
				}
			}
		}
	}

	return formatUserToken(storedToken, serviceConfig.UserAuthentication), nil
}

// HTTPServer manages the HTTP server lifecycle
type HTTPServer struct {
	server *http.Server
}

// NewHTTPServer creates a new HTTP server with the given handler and address
func NewHTTPServer(handler http.Handler, addr string) *HTTPServer {
	return &HTTPServer{
		server: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
	}
}

// Handler builders and mux assembly

// HealthHandler handles health check requests
type HealthHandler struct{}

// NewHealthHandler creates a new health handler
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// ServeHTTP implements http.Handler for health checks
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// Start starts the HTTP server
func (h *HTTPServer) Start() error {
	log.LogInfoWithFields("http", "HTTP server starting", map[string]any{
		"addr": h.server.Addr,
	})

	if err := h.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Stop gracefully stops the HTTP server
func (h *HTTPServer) Stop(ctx context.Context) error {
	log.LogInfoWithFields("http", "HTTP server stopping", map[string]any{
		"addr": h.server.Addr,
	})

	if err := h.server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	log.LogInfoWithFields("http", "HTTP server stopped", map[string]any{
		"addr": h.server.Addr,
	})
	return nil
}

// isStdioServer checks if this is a stdio-based server
func isStdioServer(config *config.MCPClientConfig) bool {
	return config.Command != ""
}

// formatUserToken formats a stored token according to the user authentication configuration
func formatUserToken(storedToken *storage.StoredToken, auth *config.UserAuthentication) string {
	if storedToken == nil {
		return ""
	}

	if storedToken.Type == storage.TokenTypeOAuth && storedToken.OAuthData != nil {
		token := storedToken.OAuthData.AccessToken
		if auth.TokenFormat != "" && auth.TokenFormat != "{{token}}" {
			return strings.ReplaceAll(auth.TokenFormat, "{{token}}", token)
		}
		return token
	}

	token := storedToken.Value
	if auth != nil && auth.TokenFormat != "" && auth.TokenFormat != "{{token}}" {
		return strings.ReplaceAll(auth.TokenFormat, "{{token}}", token)
	}
	return token
}

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
	if handler.config.RequiresUserToken && handler.userEmail != "" && handler.h.storage != nil {
		storedToken, err := handler.h.storage.GetUserToken(sessionCtx, handler.userEmail, handler.h.serverName)
		if err != nil {
			log.LogDebugWithFields("server", "No user token found", map[string]any{
				"server": handler.h.serverName,
				"user":   handler.userEmail,
			})
		} else if storedToken != nil {
			if handler.config.UserAuthentication != nil {
				userToken = formatUserToken(storedToken, handler.config.UserAuthentication)
			} else {
				userToken = storedToken.Value
			}
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
