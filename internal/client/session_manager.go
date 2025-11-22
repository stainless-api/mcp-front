package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"golang.org/x/sync/singleflight"
)

const (
	// DefaultSessionTimeout is how long idle sessions remain active
	DefaultSessionTimeout = 5 * time.Minute

	// DefaultCleanupInterval is how often to check for expired sessions
	DefaultCleanupInterval = 1 * time.Minute

	// DefaultMaxSessionsPerUser limits concurrent sessions per user
	DefaultMaxSessionsPerUser = 10
)

var (
	// ErrSessionNotFound is returned when a session doesn't exist
	ErrSessionNotFound = errors.New("session not found")

	// ErrUserLimitExceeded is returned when user has too many sessions
	ErrUserLimitExceeded = errors.New("user session limit exceeded")

	// ErrSessionCreationFailed is returned when session creation fails
	ErrSessionCreationFailed = errors.New("failed to create session")
)

// StdioSessionManager manages stdio processes for SSE sessions
type StdioSessionManager struct {
	mu              sync.RWMutex
	sessions        map[SessionKey]*StdioSession
	defaultTimeout  time.Duration
	maxPerUser      int
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	createClient    func(name string, config *config.MCPClientConfig) (*Client, error)
	wg              sync.WaitGroup
	group           singleflight.Group // Deduplicates concurrent session creation
}

// SessionKey identifies a unique session
type SessionKey struct {
	UserEmail  string // Empty for servers without requiresUserToken
	ServerName string
	SessionID  string
}

// String returns a string representation for use with singleflight
func (k SessionKey) String() string {
	return fmt.Sprintf("%s:%s:%s", k.UserEmail, k.ServerName, k.SessionID)
}

// StdioSession represents an active stdio process session
type StdioSession struct {
	client       *Client
	config       *config.MCPClientConfig
	created      time.Time
	lastAccessed atomic.Pointer[time.Time]
	cancel       context.CancelFunc
	ctx          context.Context
	key          SessionKey
}

// SessionManagerOption configures the session manager
type SessionManagerOption func(*StdioSessionManager)

// WithTimeout sets the session timeout duration
func WithTimeout(timeout time.Duration) SessionManagerOption {
	return func(sm *StdioSessionManager) {
		sm.defaultTimeout = timeout
	}
}

// WithMaxPerUser sets the maximum sessions per user
func WithMaxPerUser(max int) SessionManagerOption {
	return func(sm *StdioSessionManager) {
		sm.maxPerUser = max
	}
}

// WithCleanupInterval sets how often to run cleanup
func WithCleanupInterval(interval time.Duration) SessionManagerOption {
	return func(sm *StdioSessionManager) {
		sm.cleanupInterval = interval
	}
}

// WithClientCreator sets a custom client creator function (for testing)
func WithClientCreator(creator func(name string, config *config.MCPClientConfig) (*Client, error)) SessionManagerOption {
	return func(sm *StdioSessionManager) {
		sm.createClient = creator
	}
}

// NewStdioSessionManager creates a new session manager
func NewStdioSessionManager(opts ...SessionManagerOption) *StdioSessionManager {
	sm := &StdioSessionManager{
		sessions:        make(map[SessionKey]*StdioSession),
		defaultTimeout:  DefaultSessionTimeout,
		maxPerUser:      DefaultMaxSessionsPerUser,
		cleanupInterval: DefaultCleanupInterval,
		stopCleanup:     make(chan struct{}),
		createClient:    NewMCPClient,
	}

	for _, opt := range opts {
		opt(sm)
	}

	sm.wg.Add(1)
	go sm.startCleanupRoutine()

	return sm
}

// GetOrCreateSession returns existing session or creates new one
// Uses singleflight to ensure only one session is created even when multiple
// concurrent requests arrive for the same key. This prevents orphaned subprocesses
// and resource leaks while minimizing lock contention.
func (sm *StdioSessionManager) GetOrCreateSession(
	ctx context.Context,
	key SessionKey,
	config *config.MCPClientConfig,
	info mcp.Implementation,
	baseURL string,
	userToken string,
) (*StdioSession, error) {
	// singleflight ensures only ONE goroutine creates a session for this key
	// All concurrent requests for the same key wait and receive the same result
	v, err, _ := sm.group.Do(key.String(), func() (any, error) {
		// Fast check with RLock
		sm.mu.RLock()
		session, ok := sm.sessions[key]
		sm.mu.RUnlock()

		if ok {
			// Update last accessed time
			now := time.Now()
			session.lastAccessed.Store(&now)

			// Check if session is still alive
			select {
			case <-session.ctx.Done():
				// Process died, need to create new
				log.LogTraceWithFields("session_manager", "Found dead session, will create new", map[string]any{
					"sessionID": key.SessionID,
					"server":    key.ServerName,
					"user":      key.UserEmail,
				})
			default:
				// Session is alive, return it
				log.LogTraceWithFields("session_manager", "Reusing existing session", map[string]any{
					"sessionID": key.SessionID,
					"server":    key.ServerName,
					"user":      key.UserEmail,
				})
				return session, nil
			}
		}

		// Check user limits (acquires RLock internally)
		if err := sm.checkUserLimits(key.UserEmail); err != nil {
			return nil, err
		}

		// Create session (subprocess creation happens here, no lock held)
		return sm.createSession(key, config, userToken)
	})

	if err != nil {
		return nil, err
	}

	return v.(*StdioSession), nil
}

// GetSession retrieves an existing session
func (sm *StdioSessionManager) GetSession(key SessionKey) (*StdioSession, bool) {
	sm.mu.RLock()
	session, ok := sm.sessions[key]
	sm.mu.RUnlock()

	if ok {
		now := time.Now()
		lastAccessed := session.lastAccessed.Load()
		session.lastAccessed.Store(&now)

		log.LogTraceWithFields("session_manager", "Session accessed", map[string]any{
			"sessionID":       key.SessionID,
			"server":          key.ServerName,
			"user":            key.UserEmail,
			"lastAccessed":    lastAccessed,
			"timeSinceAccess": now.Sub(*lastAccessed).String(),
		})

		select {
		case <-session.ctx.Done():
			// Process died, remove it
			log.LogTraceWithFields("session_manager", "Session context cancelled, removing", map[string]any{
				"sessionID": key.SessionID,
				"server":    key.ServerName,
				"user":      key.UserEmail,
			})
			if err := sm.RemoveSession(key); err != nil {
				log.LogErrorWithFields("session_manager", "Failed to remove dead session", map[string]any{
					"sessionID": key.SessionID,
					"server":    key.ServerName,
					"user":      key.UserEmail,
					"error":     err.Error(),
				})
			}
			return nil, false
		default:
			return session, true
		}
	}

	log.LogTraceWithFields("session_manager", "Session not found", map[string]any{
		"sessionID": key.SessionID,
		"server":    key.ServerName,
		"user":      key.UserEmail,
	})

	return nil, false
}

// RemoveSession removes a session and cleans up its resources
// Returns error if session cleanup fails (e.g., subprocess won't terminate)
func (sm *StdioSessionManager) RemoveSession(key SessionKey) error {
	sm.mu.Lock()
	session, ok := sm.sessions[key]
	if ok {
		delete(sm.sessions, key)
		log.LogTraceWithFields("session_manager", "Removing session from map", map[string]any{
			"sessionID": key.SessionID,
			"server":    key.ServerName,
			"user":      key.UserEmail,
		})
	}
	remainingSessions := len(sm.sessions)
	sm.mu.Unlock()

	if !ok {
		return nil
	}

	// Cancel context to signal shutdown
	session.cancel()

	// Close the client
	if err := session.client.Close(); err != nil {
		log.LogErrorWithFields("session_manager", "Failed to close client", map[string]any{
			"error":     err.Error(),
			"sessionID": key.SessionID,
			"server":    key.ServerName,
			"user":      key.UserEmail,
		})
		return fmt.Errorf("failed to close session %s: %w", key.SessionID, err)
	}

	log.LogInfoWithFields("session_manager", "Removed session", map[string]any{
		"sessionID": key.SessionID,
		"server":    key.ServerName,
		"user":      key.UserEmail,
	})

	log.LogTraceWithFields("session_manager", "Session removed with details", map[string]any{
		"sessionID":         key.SessionID,
		"server":            key.ServerName,
		"user":              key.UserEmail,
		"created":           session.created,
		"duration":          time.Since(session.created).String(),
		"lastAccessed":      session.lastAccessed.Load(),
		"remainingSessions": remainingSessions,
	})

	return nil
}

// Shutdown gracefully shuts down the session manager
func (sm *StdioSessionManager) Shutdown() {
	// Stop cleanup routine
	close(sm.stopCleanup)
	sm.wg.Wait()

	sm.mu.Lock()
	sessions := make([]*StdioSession, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	sm.mu.Unlock()

	// Clean up all sessions
	for _, session := range sessions {
		if err := sm.RemoveSession(session.key); err != nil {
			log.LogErrorWithFields("shutdown", "Failed to remove session during shutdown", map[string]any{
				"sessionID": session.key.SessionID,
				"server":    session.key.ServerName,
				"user":      session.key.UserEmail,
				"error":     err.Error(),
			})
		}
	}
}

// GetClient returns the MCP client for this session
func (s *StdioSession) GetClient() *Client {
	return s.client
}

// DiscoverAndRegisterCapabilities discovers and registers capabilities from the stdio process
func (s *StdioSession) DiscoverAndRegisterCapabilities(
	ctx context.Context,
	mcpServer *server.MCPServer,
	userEmail string,
	requiresToken bool,
	tokenStore storage.UserTokenStore,
	serverName string,
	setupBaseURL string,
	userAuth *config.UserAuthentication,
	session server.ClientSession,
) error {
	// Initialize the client
	if s.client.needManualStart {
		if err := s.client.client.Start(ctx); err != nil {
			return err
		}
	}

	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{
		Name:    serverName,
		Version: "1.0",
	}
	initRequest.Params.Capabilities = mcp.ClientCapabilities{
		Experimental: make(map[string]any),
		Roots:        nil,
		Sampling:     nil,
	}

	_, err := s.client.client.Initialize(ctx, initRequest)
	if err != nil {
		return err
	}
	log.Logf("<%s> Successfully initialized MCP client", serverName)

	// Start capability discovery
	log.LogInfoWithFields("client", "Starting MCP capability discovery", map[string]any{
		"server": serverName,
	})

	log.LogTraceWithFields("client", "Starting capability discovery", map[string]any{
		"server":            serverName,
		"sessionID":         session.SessionID(),
		"userEmail":         userEmail,
		"requiresUserToken": requiresToken,
		"hasTokenSetup":     userAuth != nil,
	})

	// Discover and register tools
	if err := s.client.addToolsToServer(ctx, mcpServer, userEmail, requiresToken, tokenStore, serverName, setupBaseURL, userAuth, session); err != nil {
		return err
	}

	// Discover and register prompts
	_ = s.client.addPromptsToServer(ctx, mcpServer)

	// Discover and register resources
	_ = s.client.addResourcesToServer(ctx, mcpServer)

	// Discover and register resource templates
	_ = s.client.addResourceTemplatesToServer(ctx, mcpServer)

	log.LogInfoWithFields("client", "MCP capability discovery completed", map[string]any{
		"server":            serverName,
		"userTokenRequired": requiresToken,
	})

	log.LogTraceWithFields("client", "Capability discovery completed", map[string]any{
		"server":              serverName,
		"sessionID":           session.SessionID(),
		"userEmail":           userEmail,
		"requiresUserToken":   requiresToken,
		"toolsRegistered":     true,
		"promptsRegistered":   true,
		"resourcesRegistered": true,
	})

	// Start ping task if needed
	if s.client.needPing {
		go s.client.startPingTask(ctx)
	}

	return nil
}

// checkUserLimits verifies user hasn't exceeded session limits
func (sm *StdioSessionManager) checkUserLimits(userEmail string) error {
	if userEmail == "" {
		// No limits for anonymous/non-user-specific servers
		return nil
	}

	if sm.maxPerUser == 0 {
		// 0 means unlimited
		return nil
	}

	count := sm.getUserSessionCount(userEmail)
	if count >= sm.maxPerUser {
		log.LogWarnWithFields("session_manager", "User session limit exceeded", map[string]any{
			"user":  userEmail,
			"count": count,
			"limit": sm.maxPerUser,
		})
		return fmt.Errorf("%w: user %s has %d sessions (limit: %d)",
			ErrUserLimitExceeded, userEmail, count, sm.maxPerUser)
	}

	log.LogTraceWithFields("session_manager", "User session limit check passed", map[string]any{
		"user":            userEmail,
		"currentSessions": count,
		"maxPerUser":      sm.maxPerUser,
		"remaining":       sm.maxPerUser - count,
	})

	return nil
}

// getUserSessionCount counts sessions for a specific user
func (sm *StdioSessionManager) getUserSessionCount(userEmail string) int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for key := range sm.sessions {
		if key.UserEmail == userEmail {
			count++
		}
	}

	return count
}

// createSession creates a new stdio session
func (sm *StdioSessionManager) createSession(
	key SessionKey,
	config *config.MCPClientConfig,
	userToken string,
) (*StdioSession, error) {
	// Create an independent context for the stdio session. We intentionally use
	// context.Background() instead of the HTTP request context because stdio
	// sessions are long-lived processes that must persist across multiple HTTP
	// requests. The session will be cleaned up by the timeout-based cleanup
	// routine, not by HTTP request cancellation.
	sessionCtx, cancel := context.WithCancel(context.Background())

	if userToken != "" && config.RequiresUserToken {
		config = config.ApplyUserToken(userToken)
	}

	// Subprocess creation happens without lock (can be slow)
	client, err := sm.createClient(key.ServerName, config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%w: %v", ErrSessionCreationFailed, err)
	}

	now := time.Now()
	session := &StdioSession{
		client:  client,
		config:  config,
		created: now,
		cancel:  cancel,
		ctx:     sessionCtx,
		key:     key,
	}
	session.lastAccessed.Store(&now)

	// Store session (short lock for map write)
	sm.mu.Lock()
	sm.sessions[key] = session
	totalSessions := len(sm.sessions)
	sm.mu.Unlock()

	log.LogInfoWithFields("session_manager", "Created new session", map[string]any{
		"sessionID": key.SessionID,
		"server":    key.ServerName,
		"user":      key.UserEmail,
	})

	log.LogTraceWithFields("session_manager", "Session created with details", map[string]any{
		"sessionID":       key.SessionID,
		"server":          key.ServerName,
		"user":            key.UserEmail,
		"timeout":         sm.defaultTimeout.String(),
		"maxPerUser":      sm.maxPerUser,
		"cleanupInterval": sm.cleanupInterval.String(),
		"totalSessions":   totalSessions,
	})

	return session, nil
}

// startCleanupRoutine periodically removes timed-out sessions
func (sm *StdioSessionManager) startCleanupRoutine() {
	defer sm.wg.Done()

	ticker := time.NewTicker(sm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.cleanupTimedOutSessions()
		case <-sm.stopCleanup:
			return
		}
	}
}

// cleanupTimedOutSessions removes sessions that have timed out
func (sm *StdioSessionManager) cleanupTimedOutSessions() {
	now := time.Now()

	// Find timed out sessions
	sm.mu.RLock()
	timedOut := make([]SessionKey, 0)
	totalSessions := len(sm.sessions)
	activeSessions := 0
	for key, session := range sm.sessions {
		lastAccessed := session.lastAccessed.Load()
		if lastAccessed != nil && now.Sub(*lastAccessed) > sm.defaultTimeout {
			timedOut = append(timedOut, key)
		} else {
			activeSessions++
		}
	}
	sm.mu.RUnlock()

	if totalSessions > 0 || len(timedOut) > 0 {
		log.LogTraceWithFields("session_manager", "Session cleanup cycle", map[string]any{
			"totalSessions":    totalSessions,
			"activeSessions":   activeSessions,
			"timedOutSessions": len(timedOut),
			"timeout":          sm.defaultTimeout.String(),
		})
	}

	for _, key := range timedOut {
		log.LogInfoWithFields("session_manager", "Removing timed out session", map[string]any{
			"sessionID": key.SessionID,
			"server":    key.ServerName,
			"user":      key.UserEmail,
			"timeout":   sm.defaultTimeout,
		})
		if err := sm.RemoveSession(key); err != nil {
			log.LogErrorWithFields("session_cleanup", "Failed to remove timed out session", map[string]any{
				"sessionID": key.SessionID,
				"server":    key.ServerName,
				"user":      key.UserEmail,
				"error":     err.Error(),
			})
		}
	}
}
