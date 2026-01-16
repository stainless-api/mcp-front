package internal

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/inline"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/server"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/ory/fosite"
)

// MCPFront represents the complete MCP proxy application
type MCPFront struct {
	config         config.Config
	httpServer     *server.HTTPServer
	sessionManager *client.StdioSessionManager
	storage        storage.Storage
}

// NewMCPFront creates a new MCP proxy application with all dependencies built
func NewMCPFront(ctx context.Context, cfg config.Config) (*MCPFront, error) {
	log.LogInfoWithFields("mcpfront", "Building MCP proxy application", map[string]any{
		"baseURL":    cfg.Proxy.BaseURL,
		"mcpServers": len(cfg.MCPServers),
	})

	// Parse base URL
	baseURL, err := url.Parse(cfg.Proxy.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Setup storage (always available, independent of OAuth)
	store, err := setupStorage(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to setup storage: %w", err)
	}

	// Setup authentication (OAuth components and service client)
	oauthProvider, sessionEncryptor, authConfig, serviceOAuthClient, err := setupAuthentication(ctx, cfg, store)
	if err != nil {
		return nil, fmt.Errorf("failed to setup authentication: %w", err)
	}

	// Create session manager for stdio servers with configurable timeouts
	sessionTimeout := 5 * time.Minute
	cleanupInterval := 1 * time.Minute
	maxPerUser := 10

	// Use config values if available
	if cfg.Proxy.Sessions != nil {
		if cfg.Proxy.Sessions.Timeout > 0 {
			sessionTimeout = cfg.Proxy.Sessions.Timeout
			log.LogInfoWithFields("mcpfront", "Using configured session timeout", map[string]any{
				"timeout": sessionTimeout,
			})
		}
		if cfg.Proxy.Sessions.CleanupInterval > 0 {
			cleanupInterval = cfg.Proxy.Sessions.CleanupInterval
			log.LogInfoWithFields("mcpfront", "Using configured cleanup interval", map[string]any{
				"interval": cleanupInterval,
			})
		}
		maxPerUser = cfg.Proxy.Sessions.MaxPerUser
	}

	sessionManager := client.NewStdioSessionManager(
		client.WithTimeout(sessionTimeout),
		client.WithMaxPerUser(maxPerUser),
		client.WithCleanupInterval(cleanupInterval),
	)

	// Create user token service
	userTokenService := server.NewUserTokenService(store, serviceOAuthClient)

	info := mcp.Implementation{
		Name:    cfg.Proxy.Name,
		Version: "dev",
	}

	// Build complete HTTP handler with all routing and dependencies
	mux, err := buildHTTPHandler(
		cfg,
		store,
		oauthProvider,
		sessionEncryptor,
		authConfig,
		serviceOAuthClient,
		sessionManager,
		userTokenService,
		baseURL.String(),
		info,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP handler: %w", err)
	}

	// Create clean HTTP server with just the handler and address
	httpServer := server.NewHTTPServer(mux, cfg.Proxy.Addr)

	return &MCPFront{
		config:         cfg,
		httpServer:     httpServer,
		sessionManager: sessionManager,
		storage:        store,
	}, nil
}

// Run starts and manages the complete MCP proxy application lifecycle
func (m *MCPFront) Run() error {
	log.LogInfoWithFields("mcpfront", "Starting MCP proxy application", map[string]any{
		"addr": m.config.Proxy.Addr,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to signal errors that should trigger shutdown
	errChan := make(chan error, 1)

	// Start HTTP server
	go func() {
		if err := m.httpServer.Start(); err != nil {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start session manager cleanup (if needed)
	// The session manager already starts its cleanup goroutine internally,
	// but this is where we could start other background services

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var shutdownReason string
	select {
	case sig := <-sigChan:
		shutdownReason = fmt.Sprintf("signal %v", sig)
		log.LogInfoWithFields("mcpfront", "Received shutdown signal", map[string]any{
			"signal": sig.String(),
		})
	case err := <-errChan:
		shutdownReason = fmt.Sprintf("error: %v", err)
		log.LogErrorWithFields("mcpfront", "Shutting down due to error", map[string]any{
			"error": err.Error(),
		})
	case <-ctx.Done():
		shutdownReason = "context cancelled"
		log.LogInfoWithFields("mcpfront", "Context cancelled, shutting down", nil)
	}

	// Graceful shutdown
	log.LogInfoWithFields("mcpfront", "Starting graceful shutdown", map[string]any{
		"reason":  shutdownReason,
		"timeout": "30s",
	})
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop HTTP server
	if err := m.httpServer.Stop(shutdownCtx); err != nil {
		log.LogErrorWithFields("mcpfront", "HTTP server shutdown error", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	// Shutdown session manager
	if m.sessionManager != nil {
		m.sessionManager.Shutdown()
	}

	log.LogInfoWithFields("mcpfront", "Application shutdown complete", map[string]any{
		"reason": shutdownReason,
	})
	return nil
}

// setupStorage creates storage based on configuration, independent of OAuth
func setupStorage(ctx context.Context, cfg config.Config) (storage.Storage, error) {
	// Check if OAuth config provides storage configuration
	if oauthAuth := cfg.Proxy.Auth; oauthAuth != nil {
		if oauthAuth.Storage == "firestore" {
			log.LogInfoWithFields("storage", "Using Firestore storage", map[string]any{
				"project":    oauthAuth.GCPProject,
				"database":   oauthAuth.FirestoreDatabase,
				"collection": oauthAuth.FirestoreCollection,
			})
			// Create encryptor for Firestore storage
			encryptor, err := crypto.NewEncryptor([]byte(oauthAuth.EncryptionKey))
			if err != nil {
				return nil, fmt.Errorf("failed to create encryptor: %w", err)
			}
			firestoreStorage, err := storage.NewFirestoreStorage(
				ctx,
				oauthAuth.GCPProject,
				oauthAuth.FirestoreDatabase,
				oauthAuth.FirestoreCollection,
				encryptor,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create Firestore storage: %w", err)
			}
			return firestoreStorage, nil
		}
	}

	// Default to memory storage
	log.LogInfoWithFields("storage", "Using in-memory storage", map[string]any{})
	return storage.NewMemoryStorage(), nil
}

// setupAuthentication creates individual OAuth components using clean constructors
func setupAuthentication(ctx context.Context, cfg config.Config, store storage.Storage) (fosite.OAuth2Provider, crypto.Encryptor, config.OAuthAuthConfig, *auth.ServiceOAuthClient, error) {
	oauthAuth := cfg.Proxy.Auth
	if oauthAuth == nil {
		// OAuth not configured
		return nil, nil, config.OAuthAuthConfig{}, nil, nil
	}

	log.LogDebug("initializing OAuth components")

	// Generate or validate JWT secret using clean constructor
	jwtSecret, err := oauth.GenerateJWTSecret(string(oauthAuth.JWTSecret))
	if err != nil {
		return nil, nil, config.OAuthAuthConfig{}, nil, fmt.Errorf("failed to setup JWT secret: %w", err)
	}

	// Create session encryptor using clean constructor
	encryptionKey := []byte(oauthAuth.EncryptionKey)
	sessionEncryptor, err := oauth.NewSessionEncryptor(encryptionKey)
	if err != nil {
		return nil, nil, config.OAuthAuthConfig{}, nil, fmt.Errorf("failed to create session encryptor: %w", err)
	}

	// Create OAuth provider using clean constructor
	oauthProvider, err := oauth.NewOAuthProvider(*oauthAuth, store, jwtSecret)
	if err != nil {
		return nil, nil, config.OAuthAuthConfig{}, nil, fmt.Errorf("failed to create OAuth provider: %w", err)
	}

	// Create OAuth client for service authentication and token refresh
	serviceOAuthClient := auth.NewServiceOAuthClient(store, cfg.Proxy.BaseURL, encryptionKey)

	// Initialize admin users if admin is enabled
	if cfg.Proxy.Admin != nil && cfg.Proxy.Admin.Enabled {
		for _, adminEmail := range cfg.Proxy.Admin.AdminEmails {
			// Upsert admin user
			if err := store.UpsertUser(ctx, adminEmail); err != nil {
				log.LogWarnWithFields("mcpfront", "Failed to initialize admin user", map[string]any{
					"email": adminEmail,
					"error": err.Error(),
				})
				continue
			}
			// Set as admin
			if err := store.SetUserAdmin(ctx, adminEmail, true); err != nil {
				log.LogWarnWithFields("mcpfront", "Failed to set user as admin", map[string]any{
					"email": adminEmail,
					"error": err.Error(),
				})
			}
		}
	}

	return oauthProvider, sessionEncryptor, *oauthAuth, serviceOAuthClient, nil
}

// buildHTTPHandler creates the complete HTTP handler with all routing and middleware
func buildHTTPHandler(
	cfg config.Config,
	storage storage.Storage,
	oauthProvider fosite.OAuth2Provider,
	sessionEncryptor crypto.Encryptor,
	authConfig config.OAuthAuthConfig,
	serviceOAuthClient *auth.ServiceOAuthClient,
	sessionManager *client.StdioSessionManager,
	userTokenService *server.UserTokenService,
	baseURL string,
	info mcp.Implementation,
) (http.Handler, error) {
	// Create mux and register all routes with dependency injection
	mux := http.NewServeMux()
	basePath := cfg.Proxy.BasePath

	route := func(path string) string {
		if basePath == "/" {
			return path
		}
		return basePath + path
	}

	// Build common middleware
	corsMiddleware := server.NewCORSMiddleware(authConfig.AllowedOrigins)
	oauthLogger := server.NewLoggerMiddleware("oauth")
	mcpLogger := server.NewLoggerMiddleware("mcp")
	tokenLogger := server.NewLoggerMiddleware("tokens")
	adminLogger := server.NewLoggerMiddleware("admin")
	mcpRecover := server.NewRecoverMiddleware("mcp")
	oauthRecover := server.NewRecoverMiddleware("oauth")

	mux.Handle("/health", server.NewHealthHandler())

	// Create browser state token for SSO middleware (used by both OAuth and admin routes)
	var browserStateToken *crypto.TokenSigner
	if authConfig.EncryptionKey != "" {
		token := crypto.NewTokenSigner([]byte(authConfig.EncryptionKey), 10*time.Minute)
		browserStateToken = &token
	}

	// Register OAuth endpoints if OAuth is enabled
	if oauthProvider != nil {
		// Build OAuth middleware
		oauthMiddleware := []server.MiddlewareFunc{
			corsMiddleware,
			oauthLogger,
			oauthRecover,
		}

		// Create OAuth auth handlers with dependency injection
		authHandlers := server.NewAuthHandlers(
			oauthProvider,
			authConfig,
			storage,
			sessionEncryptor,
			cfg.MCPServers,
			serviceOAuthClient,
		)

		// Register OAuth endpoints
		mux.Handle(route("/.well-known/oauth-authorization-server"), server.ChainMiddleware(http.HandlerFunc(authHandlers.WellKnownHandler), oauthMiddleware...))
		// Per-service protected resource metadata (RFC 9728 Section 5.2)
		// Clients discover service-specific resource URIs for per-service audience validation (RFC 8707)
		mux.Handle(route("/.well-known/oauth-protected-resource/{service}"), server.ChainMiddleware(http.HandlerFunc(authHandlers.ServiceProtectedResourceMetadataHandler), oauthMiddleware...))
		// Base protected resource metadata endpoint - returns 404 directing clients to per-service endpoints
		mux.Handle(route("/.well-known/oauth-protected-resource"), server.ChainMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jsonwriter.WriteNotFound(w, "Use /.well-known/oauth-protected-resource/{service} for per-service metadata")
		}), oauthMiddleware...))
		mux.Handle(route("/authorize"), server.ChainMiddleware(http.HandlerFunc(authHandlers.AuthorizeHandler), oauthMiddleware...))
		mux.Handle(route("/oauth/callback"), server.ChainMiddleware(http.HandlerFunc(authHandlers.GoogleCallbackHandler), oauthMiddleware...))
		mux.Handle(route("/token"), server.ChainMiddleware(http.HandlerFunc(authHandlers.TokenHandler), oauthMiddleware...))
		mux.Handle(route("/register"), server.ChainMiddleware(http.HandlerFunc(authHandlers.RegisterHandler), oauthMiddleware...))
		mux.Handle(route("/clients/{client_id}"), server.ChainMiddleware(http.HandlerFunc(authHandlers.ClientMetadataHandler), oauthMiddleware...))

		// Register protected token endpoints
		tokenMiddleware := []server.MiddlewareFunc{
			corsMiddleware,
			tokenLogger,
			server.NewBrowserSSOMiddleware(authConfig, sessionEncryptor, browserStateToken),
			mcpRecover,
		}

		// Create token handlers
		tokenHandlers := server.NewTokenHandlers(storage, cfg.MCPServers, true, serviceOAuthClient)

		// Token management UI endpoints
		mux.Handle(route("/my/tokens"), server.ChainMiddleware(http.HandlerFunc(tokenHandlers.ListTokensHandler), tokenMiddleware...))
		mux.Handle(route("/my/tokens/set"), server.ChainMiddleware(http.HandlerFunc(tokenHandlers.SetTokenHandler), tokenMiddleware...))
		mux.Handle(route("/my/tokens/delete"), server.ChainMiddleware(http.HandlerFunc(tokenHandlers.DeleteTokenHandler), tokenMiddleware...))

		// OAuth interstitial page and completion endpoint
		mux.Handle(route("/oauth/services"), server.ChainMiddleware(http.HandlerFunc(authHandlers.ServiceSelectionHandler), tokenMiddleware...))
		mux.Handle(route("/oauth/complete"), server.ChainMiddleware(http.HandlerFunc(authHandlers.CompleteOAuthHandler), tokenMiddleware...))

		// Register service OAuth endpoints
		serviceAuthHandlers := server.NewServiceAuthHandlers(serviceOAuthClient, cfg.MCPServers, storage)
		mux.HandleFunc(route("/oauth/callback/{service}"), serviceAuthHandlers.CallbackHandler)
		mux.Handle(route("/oauth/connect"), server.ChainMiddleware(http.HandlerFunc(serviceAuthHandlers.ConnectHandler), tokenMiddleware...))
		mux.Handle(route("/oauth/disconnect"), server.ChainMiddleware(http.HandlerFunc(serviceAuthHandlers.DisconnectHandler), tokenMiddleware...))
	}

	// Setup MCP server endpoints
	sseServers := make(map[string]*mcpserver.SSEServer) // Track SSE servers for stdio servers

	for serverName, serverConfig := range cfg.MCPServers {
		log.LogInfoWithFields("server", "Registering MCP server", map[string]any{
			"name":                serverName,
			"transport_type":      serverConfig.TransportType,
			"requires_user_token": serverConfig.RequiresUserToken,
		})

		var handler http.Handler
		var err error
		var mcpServer *mcpserver.MCPServer
		var sseServer *mcpserver.SSEServer

		// For inline servers, create a custom handler
		if serverConfig.TransportType == config.MCPClientTypeInline {
			handler, err = buildInlineHandler(serverName, serverConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create inline handler for %s: %w", serverName, err)
			}
		} else {
			// For stdio/SSE servers
			if isStdioServer(serverConfig) {
				sseServer, mcpServer, err = buildStdioSSEServer(serverName, baseURL, sessionManager)
				if err != nil {
					return nil, fmt.Errorf("failed to create SSE server for %s: %w", serverName, err)
				}
				sseServers[serverName] = sseServer
			}

			// Create MCP handler for stdio/SSE servers
			handler = server.NewMCPHandler(
				serverName,
				serverConfig,
				storage,
				baseURL,
				info,
				sessionManager,
				sseServers[serverName],
				mcpServer,
				userTokenService.GetUserToken,
			)
		}

		// Setup middlewares for this MCP server
		mcpMiddlewares := []server.MiddlewareFunc{
			mcpLogger,
			corsMiddleware,
		}

		// Add OAuth validation if OAuth is enabled
		if oauthProvider != nil {
			mcpMiddlewares = append(mcpMiddlewares, oauth.NewValidateTokenMiddleware(oauthProvider, authConfig.Issuer))
		}

		// Add service auth middleware if configured
		if len(serverConfig.ServiceAuths) > 0 {
			mcpMiddlewares = append(mcpMiddlewares, server.NewServiceAuthMiddleware(serverConfig.ServiceAuths))
		}

		// Recovery middleware should be last (outermost)
		mcpMiddlewares = append(mcpMiddlewares, mcpRecover)

		mux.Handle(route("/"+serverName+"/"), server.ChainMiddleware(handler, mcpMiddlewares...))
	}

	// Setup admin routes if admin is enabled
	if cfg.Proxy.Admin != nil && cfg.Proxy.Admin.Enabled {
		log.LogInfoWithFields("server", "Admin UI enabled", map[string]any{
			"admin_emails": cfg.Proxy.Admin.AdminEmails,
		})

		// Get encryption key from OAuth config
		var encryptionKey string
		if oauthAuth := cfg.Proxy.Auth; oauthAuth != nil {
			encryptionKey = string(oauthAuth.EncryptionKey)
		}

		// Create admin handlers
		adminHandlers := server.NewAdminHandlers(storage, cfg, sessionManager, encryptionKey)

		// Build admin middleware
		adminMiddleware := []server.MiddlewareFunc{
			corsMiddleware,
			adminLogger,
		}

		// Add browser SSO if OAuth is enabled
		if oauthProvider != nil {
			// Reuse the same browserStateToken created earlier for consistency
			adminMiddleware = append(adminMiddleware, server.NewBrowserSSOMiddleware(authConfig, sessionEncryptor, browserStateToken))
		}

		// Add admin check middleware
		adminMiddleware = append(adminMiddleware, server.NewAdminMiddleware(cfg.Proxy.Admin, storage))

		// Recovery middleware last
		adminMiddleware = append(adminMiddleware, mcpRecover)

		// Register admin routes
		mux.Handle(route("/admin"), server.ChainMiddleware(http.HandlerFunc(adminHandlers.DashboardHandler), adminMiddleware...))
		mux.Handle(route("/admin/users"), server.ChainMiddleware(http.HandlerFunc(adminHandlers.UserActionHandler), adminMiddleware...))
		mux.Handle(route("/admin/sessions"), server.ChainMiddleware(http.HandlerFunc(adminHandlers.SessionActionHandler), adminMiddleware...))
		mux.Handle(route("/admin/logging"), server.ChainMiddleware(http.HandlerFunc(adminHandlers.LoggingActionHandler), adminMiddleware...))
	}

	log.LogInfoWithFields("server", "MCP proxy server initialized", nil)
	return mux, nil
}

// buildInlineHandler creates an inline MCP handler
func buildInlineHandler(serverName string, serverConfig *config.MCPClientConfig) (http.Handler, error) {
	// Resolve inline config
	inlineConfig, resolvedTools, err := inline.ResolveConfig(serverConfig.InlineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve inline config: %w", err)
	}

	// Create inline server
	inlineServer := inline.NewServer(serverName, inlineConfig, resolvedTools)

	// Create inline handler
	handler := inline.NewHandler(serverName, inlineServer)

	log.LogInfoWithFields("server", "Created inline MCP server", map[string]any{
		"name":  serverName,
		"tools": len(resolvedTools),
	})

	return handler, nil
}

// buildStdioSSEServer creates an SSE server for stdio MCP servers
func buildStdioSSEServer(serverName, baseURL string, sessionManager *client.StdioSessionManager) (*mcpserver.SSEServer, *mcpserver.MCPServer, error) {
	// Create hooks for session management
	hooks := &mcpserver.Hooks{}

	// Store reference to server name for use in hooks
	currentServerName := serverName

	// Setup hooks that will be called when sessions are created/destroyed
	hooks.AddOnRegisterSession(func(sessionCtx context.Context, session mcpserver.ClientSession) {
		// Extract handler from context
		if handler, ok := sessionCtx.Value(server.SessionHandlerKey{}).(*server.SessionRequestHandler); ok {
			// Handle session registration (MCP server is already set in handler)
			server.HandleSessionRegistration(sessionCtx, session, handler, sessionManager)
		} else {
			log.LogErrorWithFields("server", "No session handler in context", map[string]any{
				"sessionID": session.SessionID(),
				"server":    currentServerName,
			})
		}
	})

	hooks.AddOnUnregisterSession(func(sessionCtx context.Context, session mcpserver.ClientSession) {
		// Extract handler from context
		if handler, ok := sessionCtx.Value(server.SessionHandlerKey{}).(*server.SessionRequestHandler); ok {
			// Handle session cleanup
			key := client.SessionKey{
				UserEmail:  handler.GetUserEmail(),
				ServerName: handler.GetServerName(),
				SessionID:  session.SessionID(),
			}
			if err := sessionManager.RemoveSession(key); err != nil {
				log.LogErrorWithFields("server", "Failed to remove session on unregister", map[string]any{
					"sessionID": session.SessionID(),
					"user":      handler.GetUserEmail(),
					"error":     err.Error(),
				})
			}

			if storage := handler.GetStorage(); storage != nil {
				if err := storage.RevokeSession(sessionCtx, session.SessionID()); err != nil {
					log.LogWarnWithFields("server", "Failed to revoke session from storage", map[string]any{
						"error":     err.Error(),
						"sessionID": session.SessionID(),
						"user":      handler.GetUserEmail(),
					})
				}
			}

			log.LogInfoWithFields("server", "Session unregistered and cleaned up", map[string]any{
				"sessionID": session.SessionID(),
				"server":    currentServerName,
				"user":      handler.GetUserEmail(),
			})
		}
	})

	// Now create the MCP server with the hooks
	mcpServer := mcpserver.NewMCPServer(serverName, "1.0.0",
		mcpserver.WithHooks(hooks),
		mcpserver.WithPromptCapabilities(true),
		mcpserver.WithResourceCapabilities(true, true),
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithLogging(),
	)

	// Create the SSE server wrapper around the MCP server
	sseServer := mcpserver.NewSSEServer(mcpServer,
		mcpserver.WithStaticBasePath(serverName),
		mcpserver.WithBaseURL(baseURL),
	)

	return sseServer, mcpServer, nil
}

// isStdioServer checks if this is a stdio-based server
func isStdioServer(cfg *config.MCPClientConfig) bool {
	return cfg.TransportType == config.MCPClientTypeStdio
}
