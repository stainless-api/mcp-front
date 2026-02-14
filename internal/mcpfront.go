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
	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/dgellow/mcp-front/internal/inline"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/server"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

type MCPFront struct {
	config         config.Config
	httpServer     *server.HTTPServer
	sessionManager *client.StdioSessionManager
	storage        storage.Storage
}

func NewMCPFront(ctx context.Context, cfg config.Config) (*MCPFront, error) {
	log.LogInfoWithFields("mcpfront", "Building MCP proxy application", map[string]any{
		"baseURL":    cfg.Proxy.BaseURL,
		"mcpServers": len(cfg.MCPServers),
	})

	baseURL, err := url.Parse(cfg.Proxy.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	store, err := setupStorage(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to setup storage: %w", err)
	}

	authServer, idpProvider, sessionEncryptor, authConfig, serviceOAuthClient, err := setupAuthentication(ctx, cfg, store)
	if err != nil {
		return nil, fmt.Errorf("failed to setup authentication: %w", err)
	}

	sessionTimeout := 5 * time.Minute
	cleanupInterval := 1 * time.Minute
	maxPerUser := 10

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

	userTokenService := server.NewUserTokenService(store, serviceOAuthClient)

	info := mcp.Implementation{
		Name:    cfg.Proxy.Name,
		Version: "dev",
	}

	mux, err := buildHTTPHandler(
		cfg,
		store,
		authServer,
		idpProvider,
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

	httpServer := server.NewHTTPServer(mux, cfg.Proxy.Addr)

	return &MCPFront{
		config:         cfg,
		httpServer:     httpServer,
		sessionManager: sessionManager,
		storage:        store,
	}, nil
}

func (m *MCPFront) Run() error {
	log.LogInfoWithFields("mcpfront", "Starting MCP proxy application", map[string]any{
		"addr": m.config.Proxy.Addr,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)

	go func() {
		if err := m.httpServer.Start(); err != nil {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

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

	log.LogInfoWithFields("mcpfront", "Starting graceful shutdown", map[string]any{
		"reason":  shutdownReason,
		"timeout": "30s",
	})
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := m.httpServer.Stop(shutdownCtx); err != nil {
		log.LogErrorWithFields("mcpfront", "HTTP server shutdown error", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	if m.sessionManager != nil {
		m.sessionManager.Shutdown()
	}

	log.LogInfoWithFields("mcpfront", "Application shutdown complete", map[string]any{
		"reason": shutdownReason,
	})
	return nil
}

func setupStorage(ctx context.Context, cfg config.Config) (storage.Storage, error) {
	if oauthAuth := cfg.Proxy.Auth; oauthAuth != nil {
		if oauthAuth.Storage == "firestore" {
			log.LogInfoWithFields("storage", "Using Firestore storage", map[string]any{
				"project":    oauthAuth.GCPProject,
				"database":   oauthAuth.FirestoreDatabase,
				"collection": oauthAuth.FirestoreCollection,
			})
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

	log.LogInfoWithFields("storage", "Using in-memory storage", map[string]any{})
	return storage.NewMemoryStorage(), nil
}

func setupAuthentication(ctx context.Context, cfg config.Config, store storage.Storage) (*oauth.AuthorizationServer, idp.Provider, crypto.Encryptor, config.OAuthAuthConfig, *auth.ServiceOAuthClient, error) {
	oauthAuth := cfg.Proxy.Auth
	if oauthAuth == nil {
		return nil, nil, nil, config.OAuthAuthConfig{}, nil, nil
	}

	log.LogDebug("initializing OAuth components")

	idpProvider, err := idp.NewProvider(oauthAuth.IDP)
	if err != nil {
		return nil, nil, nil, config.OAuthAuthConfig{}, nil, fmt.Errorf("failed to create identity provider: %w", err)
	}

	log.LogInfoWithFields("mcpfront", "Identity provider configured", map[string]any{
		"type": idpProvider.Type(),
	})

	jwtSecret, err := oauth.GenerateJWTSecret(string(oauthAuth.JWTSecret))
	if err != nil {
		return nil, nil, nil, config.OAuthAuthConfig{}, nil, fmt.Errorf("failed to setup JWT secret: %w", err)
	}

	encryptionKey := []byte(oauthAuth.EncryptionKey)
	sessionEncryptor, err := oauth.NewSessionEncryptor(encryptionKey)
	if err != nil {
		return nil, nil, nil, config.OAuthAuthConfig{}, nil, fmt.Errorf("failed to create session encryptor: %w", err)
	}

	minEntropy := 8
	if config.IsDev() {
		minEntropy = 0
		log.LogWarn("Development mode enabled - OAuth security checks relaxed (state parameter entropy: %d)", minEntropy)
	}

	authServer, err := oauth.NewAuthorizationServer(oauth.AuthorizationServerConfig{
		JWTSecret:          jwtSecret,
		Issuer:             oauthAuth.Issuer,
		AccessTokenTTL:     oauthAuth.TokenTTL,
		RefreshTokenTTL:    oauthAuth.RefreshTokenTTL,
		MinStateEntropy:    minEntropy,
		RefreshTokenScopes: oauthAuth.RefreshTokenScopes,
	})
	if err != nil {
		return nil, nil, nil, config.OAuthAuthConfig{}, nil, fmt.Errorf("failed to create authorization server: %w", err)
	}

	serviceOAuthClient := auth.NewServiceOAuthClient(store, cfg.Proxy.BaseURL, encryptionKey)

	if cfg.Proxy.Admin != nil && cfg.Proxy.Admin.Enabled {
		for _, adminEmail := range cfg.Proxy.Admin.AdminEmails {
			if err := store.UpsertUser(ctx, adminEmail); err != nil {
				log.LogWarnWithFields("mcpfront", "Failed to initialize admin user", map[string]any{
					"email": adminEmail,
					"error": err.Error(),
				})
				continue
			}
			if err := store.SetUserAdmin(ctx, adminEmail, true); err != nil {
				log.LogWarnWithFields("mcpfront", "Failed to set user as admin", map[string]any{
					"email": adminEmail,
					"error": err.Error(),
				})
			}
		}
	}

	return authServer, idpProvider, sessionEncryptor, *oauthAuth, serviceOAuthClient, nil
}

func buildHTTPHandler(
	cfg config.Config,
	storage storage.Storage,
	authServer *oauth.AuthorizationServer,
	idpProvider idp.Provider,
	sessionEncryptor crypto.Encryptor,
	authConfig config.OAuthAuthConfig,
	serviceOAuthClient *auth.ServiceOAuthClient,
	sessionManager *client.StdioSessionManager,
	userTokenService *server.UserTokenService,
	baseURL string,
	info mcp.Implementation,
) (http.Handler, error) {
	mux := http.NewServeMux()
	basePath := cfg.Proxy.BasePath

	route := func(path string) string {
		if basePath == "/" {
			return path
		}
		return basePath + path
	}

	corsMiddleware := server.NewCORSMiddleware(authConfig.AllowedOrigins)
	oauthLogger := server.NewLoggerMiddleware("oauth")
	mcpLogger := server.NewLoggerMiddleware("mcp")
	tokenLogger := server.NewLoggerMiddleware("tokens")
	adminLogger := server.NewLoggerMiddleware("admin")
	mcpRecover := server.NewRecoverMiddleware("mcp")
	oauthRecover := server.NewRecoverMiddleware("oauth")

	mux.Handle("/health", server.NewHealthHandler())

	var browserStateToken *crypto.TokenSigner
	if authConfig.EncryptionKey != "" {
		token := crypto.NewTokenSigner([]byte(authConfig.EncryptionKey), 10*time.Minute)
		browserStateToken = &token
	}

	if authServer != nil {
		oauthMiddleware := []server.MiddlewareFunc{
			corsMiddleware,
			oauthLogger,
			oauthRecover,
		}

		authHandlers := server.NewAuthHandlers(
			authServer,
			authConfig,
			idpProvider,
			storage,
			sessionEncryptor,
			cfg.MCPServers,
			serviceOAuthClient,
		)

		mux.Handle(route("/.well-known/oauth-authorization-server"), server.ChainMiddleware(http.HandlerFunc(authHandlers.WellKnownHandler), oauthMiddleware...))
		mux.Handle(route("/.well-known/oauth-protected-resource/{service}"), server.ChainMiddleware(http.HandlerFunc(authHandlers.ServiceProtectedResourceMetadataHandler), oauthMiddleware...))
		mux.Handle(route("/.well-known/oauth-protected-resource"), server.ChainMiddleware(http.HandlerFunc(authHandlers.ProtectedResourceMetadataHandler), oauthMiddleware...))
		mux.Handle(route("/authorize"), server.ChainMiddleware(http.HandlerFunc(authHandlers.AuthorizeHandler), oauthMiddleware...))
		mux.Handle(route("/oauth/callback"), server.ChainMiddleware(http.HandlerFunc(authHandlers.IDPCallbackHandler), oauthMiddleware...))
		mux.Handle(route("/token"), server.ChainMiddleware(http.HandlerFunc(authHandlers.TokenHandler), oauthMiddleware...))
		mux.Handle(route("/register"), server.ChainMiddleware(http.HandlerFunc(authHandlers.RegisterHandler), oauthMiddleware...))
		mux.Handle(route("/clients/{client_id}"), server.ChainMiddleware(http.HandlerFunc(authHandlers.ClientMetadataHandler), oauthMiddleware...))

		tokenMiddleware := []server.MiddlewareFunc{
			corsMiddleware,
			tokenLogger,
			server.NewBrowserSSOMiddleware(authConfig, idpProvider, sessionEncryptor, browserStateToken),
			mcpRecover,
		}

		tokenHandlers := server.NewTokenHandlers(storage, cfg.MCPServers, true, serviceOAuthClient, []byte(authConfig.EncryptionKey))

		mux.Handle(route("/my/tokens"), server.ChainMiddleware(http.HandlerFunc(tokenHandlers.ListTokensHandler), tokenMiddleware...))
		mux.Handle(route("/my/tokens/set"), server.ChainMiddleware(http.HandlerFunc(tokenHandlers.SetTokenHandler), tokenMiddleware...))
		mux.Handle(route("/my/tokens/delete"), server.ChainMiddleware(http.HandlerFunc(tokenHandlers.DeleteTokenHandler), tokenMiddleware...))

		mux.Handle(route("/oauth/services"), server.ChainMiddleware(http.HandlerFunc(authHandlers.ServiceSelectionHandler), tokenMiddleware...))
		mux.Handle(route("/oauth/complete"), server.ChainMiddleware(http.HandlerFunc(authHandlers.CompleteOAuthHandler), tokenMiddleware...))

		serviceAuthHandlers := server.NewServiceAuthHandlers(serviceOAuthClient, cfg.MCPServers, storage)
		mux.HandleFunc(route("/oauth/callback/{service}"), serviceAuthHandlers.CallbackHandler)
		mux.Handle(route("/oauth/connect"), server.ChainMiddleware(http.HandlerFunc(serviceAuthHandlers.ConnectHandler), tokenMiddleware...))
		mux.Handle(route("/oauth/disconnect"), server.ChainMiddleware(http.HandlerFunc(serviceAuthHandlers.DisconnectHandler), tokenMiddleware...))
	}

	sseServers := make(map[string]*mcpserver.SSEServer)

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

		if serverConfig.TransportType == config.MCPClientTypeInline {
			handler, err = buildInlineHandler(serverName, serverConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create inline handler for %s: %w", serverName, err)
			}
		} else {
			if serverConfig.IsStdio() {
				sseServer, mcpServer, err = buildStdioSSEServer(serverName, baseURL, sessionManager)
				if err != nil {
					return nil, fmt.Errorf("failed to create SSE server for %s: %w", serverName, err)
				}
				sseServers[serverName] = sseServer
			}

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

		mcpMiddlewares := []server.MiddlewareFunc{
			mcpLogger,
			corsMiddleware,
		}

		if authServer != nil {
			mcpMiddlewares = append(mcpMiddlewares, oauth.NewValidateTokenMiddleware(authServer, authConfig.Issuer, authConfig.DangerouslyAcceptIssuerAudience))
		}

		if len(serverConfig.ServiceAuths) > 0 {
			mcpMiddlewares = append(mcpMiddlewares, server.NewServiceAuthMiddleware(serverConfig.ServiceAuths))
		}

		mcpMiddlewares = append(mcpMiddlewares, mcpRecover)

		mux.Handle(route("/"+serverName+"/"), server.ChainMiddleware(handler, mcpMiddlewares...))
	}

	if cfg.Proxy.Admin != nil && cfg.Proxy.Admin.Enabled {
		log.LogInfoWithFields("server", "Admin UI enabled", map[string]any{
			"admin_emails": cfg.Proxy.Admin.AdminEmails,
		})

		var encryptionKey string
		if oauthAuth := cfg.Proxy.Auth; oauthAuth != nil {
			encryptionKey = string(oauthAuth.EncryptionKey)
		}

		adminHandlers := server.NewAdminHandlers(storage, cfg, sessionManager, encryptionKey)

		adminMiddleware := []server.MiddlewareFunc{
			corsMiddleware,
			adminLogger,
		}

		if authServer != nil {
			adminMiddleware = append(adminMiddleware, server.NewBrowserSSOMiddleware(authConfig, idpProvider, sessionEncryptor, browserStateToken))
		}

		adminMiddleware = append(adminMiddleware, server.NewAdminMiddleware(cfg.Proxy.Admin, storage))
		adminMiddleware = append(adminMiddleware, mcpRecover)

		mux.Handle(route("/admin"), server.ChainMiddleware(http.HandlerFunc(adminHandlers.DashboardHandler), adminMiddleware...))
		mux.Handle(route("/admin/users"), server.ChainMiddleware(http.HandlerFunc(adminHandlers.UserActionHandler), adminMiddleware...))
		mux.Handle(route("/admin/sessions"), server.ChainMiddleware(http.HandlerFunc(adminHandlers.SessionActionHandler), adminMiddleware...))
		mux.Handle(route("/admin/logging"), server.ChainMiddleware(http.HandlerFunc(adminHandlers.LoggingActionHandler), adminMiddleware...))
	}

	log.LogInfoWithFields("server", "MCP proxy server initialized", nil)
	return mux, nil
}

func buildInlineHandler(serverName string, serverConfig *config.MCPClientConfig) (http.Handler, error) {
	inlineConfig, resolvedTools, err := inline.ResolveConfig(serverConfig.InlineConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve inline config: %w", err)
	}

	inlineServer := inline.NewServer(serverName, inlineConfig, resolvedTools)
	handler := inline.NewHandler(serverName, inlineServer)

	log.LogInfoWithFields("server", "Created inline MCP server", map[string]any{
		"name":  serverName,
		"tools": len(resolvedTools),
	})

	return handler, nil
}

func buildStdioSSEServer(serverName, baseURL string, sessionManager *client.StdioSessionManager) (*mcpserver.SSEServer, *mcpserver.MCPServer, error) {
	hooks := &mcpserver.Hooks{}
	currentServerName := serverName

	hooks.AddOnRegisterSession(func(sessionCtx context.Context, session mcpserver.ClientSession) {
		if handler, ok := sessionCtx.Value(server.SessionHandlerKey{}).(*server.SessionRequestHandler); ok {
			server.HandleSessionRegistration(sessionCtx, session, handler, sessionManager)
		} else {
			log.LogErrorWithFields("server", "No session handler in context", map[string]any{
				"sessionID": session.SessionID(),
				"server":    currentServerName,
			})
		}
	})

	hooks.AddOnUnregisterSession(func(sessionCtx context.Context, session mcpserver.ClientSession) {
		if handler, ok := sessionCtx.Value(server.SessionHandlerKey{}).(*server.SessionRequestHandler); ok {
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

	mcpServer := mcpserver.NewMCPServer(serverName, "1.0.0",
		mcpserver.WithHooks(hooks),
		mcpserver.WithPromptCapabilities(true),
		mcpserver.WithResourceCapabilities(true, true),
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithLogging(),
	)

	sseServer := mcpserver.NewSSEServer(mcpServer,
		mcpserver.WithStaticBasePath(serverName),
		mcpserver.WithBaseURL(baseURL),
	)

	return sseServer, mcpServer, nil
}
