package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgellow/mcp-front/internal/adminauth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/executiontoken"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
)

// Execution session configuration constants
const (
	// MaxTTLSeconds is the absolute maximum session lifetime (15 minutes)
	MaxTTLSeconds = 900

	// DefaultMaxTTLSeconds is the default max TTL if not specified
	DefaultMaxTTLSeconds = 900

	// DefaultIdleTimeoutSeconds is the default idle timeout (30 seconds)
	DefaultIdleTimeoutSeconds = 30

	// DefaultMaxRequests is the default maximum number of requests per session
	DefaultMaxRequests = 1000

	// MinHeartbeatInterval is the minimum time between heartbeats (10 seconds)
	MinHeartbeatInterval = 10 * time.Second
)

// ExecutionHandlers provides HTTP handlers for execution session management
type ExecutionHandlers struct {
	storage        storage.Storage
	tokenGenerator *executiontoken.Generator
	proxyBaseURL   string
	mcpServers     map[string]*config.MCPClientConfig
	adminConfig    *config.AdminConfig
}

// NewExecutionHandlers creates execution handlers with dependency injection
func NewExecutionHandlers(
	storage storage.Storage,
	tokenGenerator *executiontoken.Generator,
	proxyBaseURL string,
	mcpServers map[string]*config.MCPClientConfig,
	adminConfig *config.AdminConfig,
) *ExecutionHandlers {
	return &ExecutionHandlers{
		storage:        storage,
		tokenGenerator: tokenGenerator,
		proxyBaseURL:   proxyBaseURL,
		mcpServers:     mcpServers,
		adminConfig:    adminConfig,
	}
}

// CreateSessionRequest represents the request body for session creation
type CreateSessionRequest struct {
	ExecutionID        string   `json:"execution_id"`
	TargetService      string   `json:"target_service"`
	MaxTTLSeconds      int      `json:"max_ttl_seconds,omitempty"`      // Absolute max (default 900 = 15 min)
	IdleTimeoutSeconds int      `json:"idle_timeout_seconds,omitempty"` // Inactivity timeout (default 30s)
	AllowedPaths       []string `json:"allowed_paths,omitempty"`
	MaxRequests        int      `json:"max_requests,omitempty"` // Default 1000
}

// CreateSessionResponse represents the response for session creation
type CreateSessionResponse struct {
	SessionID       string    `json:"session_id"`
	Token           string    `json:"token"`
	ProxyURL        string    `json:"proxy_url"`
	IdleTimeout     int       `json:"idle_timeout"`       // Seconds
	MaxTTL          int       `json:"max_ttl"`            // Seconds
	ExpiresAt       time.Time `json:"expires_at"`         // When session expires due to inactivity
	MaxTTLExpiresAt time.Time `json:"max_ttl_expires_at"` // Absolute max expiry
}

// HeartbeatResponse represents the response for heartbeat
type HeartbeatResponse struct {
	ExpiresAt       time.Time `json:"expires_at"`
	MaxTTLExpiresAt time.Time `json:"max_ttl_expires_at"`
	RequestCount    int       `json:"request_count"`
}

// SessionInfo represents session information for listing
type SessionInfo struct {
	SessionID       string    `json:"session_id"`
	ExecutionID     string    `json:"execution_id"`
	User            string    `json:"user"`
	Service         string    `json:"service"`
	CreatedAt       time.Time `json:"created_at"`
	LastActivity    time.Time `json:"last_activity"`
	ExpiresAt       time.Time `json:"expires_at"`
	MaxTTLExpiresAt time.Time `json:"max_ttl_expires_at"`
	RequestCount    int       `json:"request_count"`
	MaxRequests     int       `json:"max_requests"`
}

// CreateSessionHandler handles POST /api/execution-session
func (h *ExecutionHandlers) CreateSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonwriter.WriteMethodNotAllowed(w, "Method not allowed")
		return
	}

	ctx := r.Context()

	// Get authenticated user
	userEmail, ok := oauth.GetUserFromContext(ctx)
	if !ok {
		jsonwriter.WriteUnauthorized(w, "Unauthorized")
		return
	}

	// Parse request
	var req CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonwriter.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Validate required fields
	if req.ExecutionID == "" {
		jsonwriter.WriteBadRequest(w, "execution_id is required")
		return
	}
	if req.TargetService == "" {
		jsonwriter.WriteBadRequest(w, "target_service is required")
		return
	}

	// Check service exists and is configured for proxy
	serviceConfig, exists := h.mcpServers[req.TargetService]
	if !exists {
		jsonwriter.WriteBadRequest(w, fmt.Sprintf("Unknown service: %s", req.TargetService))
		return
	}

	if serviceConfig.Proxy == nil || !serviceConfig.Proxy.Enabled {
		jsonwriter.WriteBadRequest(w, fmt.Sprintf("Service %s does not have proxy enabled", req.TargetService))
		return
	}

	// Check user has connected to this service
	_, err := h.storage.GetUserToken(ctx, userEmail, req.TargetService)
	if err != nil {
		if err == storage.ErrUserTokenNotFound {
			jsonwriter.WriteBadRequest(w, fmt.Sprintf("User not connected to service %s", req.TargetService))
		} else {
			jsonwriter.WriteInternalServerError(w, "Failed to check service connection")
		}
		return
	}

	// Set defaults
	maxTTL := time.Duration(DefaultMaxTTLSeconds) * time.Second
	if req.MaxTTLSeconds > 0 {
		if req.MaxTTLSeconds > MaxTTLSeconds {
			jsonwriter.WriteBadRequest(w, fmt.Sprintf("max_ttl_seconds cannot exceed %d seconds (%d minutes)", MaxTTLSeconds, MaxTTLSeconds/60))
			return
		}
		maxTTL = time.Duration(req.MaxTTLSeconds) * time.Second
	}

	idleTimeout := time.Duration(DefaultIdleTimeoutSeconds) * time.Second
	if req.IdleTimeoutSeconds > 0 {
		idleTimeout = time.Duration(req.IdleTimeoutSeconds) * time.Second
	}

	maxRequests := DefaultMaxRequests
	if req.MaxRequests > 0 {
		maxRequests = req.MaxRequests
	}

	// Use default allowed paths from service config if not specified
	allowedPaths := req.AllowedPaths
	if len(allowedPaths) == 0 && len(serviceConfig.Proxy.DefaultAllowedPaths) > 0 {
		allowedPaths = serviceConfig.Proxy.DefaultAllowedPaths
	}

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		log.LogError("Failed to generate session ID: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to generate session ID")
		return
	}

	// Create session
	now := time.Now()
	session := &storage.ExecutionSession{
		SessionID:     sessionID,
		ExecutionID:   req.ExecutionID,
		UserEmail:     userEmail,
		TargetService: req.TargetService,
		AllowedPaths:  allowedPaths,
		CreatedAt:     now,
		LastHeartbeat: now,
		ExpiresAt:     now.Add(idleTimeout),
		IdleTimeout:   idleTimeout,
		MaxTTL:        maxTTL,
		MaxRequests:   maxRequests,
		RequestCount:  0,
	}

	err = h.storage.CreateExecutionSession(ctx, session)
	if err != nil {
		log.LogError("Failed to create execution session: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to create session")
		return
	}

	// Generate token
	token, err := h.tokenGenerator.Generate(sessionID)
	if err != nil {
		log.LogError("Failed to generate execution token: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to generate token")
		return
	}

	// Build proxy URL
	proxyURL := fmt.Sprintf("%s/proxy/%s", h.proxyBaseURL, req.TargetService)

	log.LogInfoWithFields("execution_handlers", "Created execution session", map[string]any{
		"session_id":   sessionID,
		"execution_id": req.ExecutionID,
		"user":         userEmail,
		"service":      req.TargetService,
		"max_ttl":      maxTTL.String(),
		"idle_timeout": idleTimeout.String(),
	})

	jsonwriter.Write(w, CreateSessionResponse{
		SessionID:       sessionID,
		Token:           token,
		ProxyURL:        proxyURL,
		IdleTimeout:     int(idleTimeout.Seconds()),
		MaxTTL:          int(maxTTL.Seconds()),
		ExpiresAt:       session.ExpiresAt,
		MaxTTLExpiresAt: session.CreatedAt.Add(session.MaxTTL),
	})
}

// HeartbeatHandler handles POST /api/execution-session/{session_id}/heartbeat
func (h *ExecutionHandlers) HeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonwriter.WriteMethodNotAllowed(w, "Method not allowed")
		return
	}

	ctx := r.Context()
	sessionID := r.PathValue("session_id")

	// Get session
	session, err := h.storage.GetExecutionSession(ctx, sessionID)
	if err != nil {
		if err == storage.ErrSessionNotFound {
			jsonwriter.WriteNotFound(w, "Session not found or expired")
		} else {
			jsonwriter.WriteInternalServerError(w, "Failed to get session")
		}
		return
	}

	// Check if expired
	if session.IsExpired() {
		jsonwriter.WriteUnauthorized(w, "Session has expired")
		return
	}

	// Verify user owns this session (or is admin)
	userEmail, ok := oauth.GetUserFromContext(ctx)
	isAdmin := h.adminConfig != nil && adminauth.IsAdmin(ctx, userEmail, h.adminConfig, h.storage)
	if !ok || (session.UserEmail != userEmail && !isAdmin) {
		jsonwriter.WriteForbidden(w, "Cannot access another user's session")
		return
	}

	// Check rate limit (prevent heartbeat spam)
	if time.Since(session.LastHeartbeat) < MinHeartbeatInterval {
		jsonwriter.WriteBadRequest(w, fmt.Sprintf("Heartbeat too frequent (min %s interval)", MinHeartbeatInterval))
		return
	}

	// Record activity
	err = h.storage.RecordSessionActivity(ctx, sessionID)
	if err != nil {
		log.LogError("Failed to record session activity: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to update session")
		return
	}

	// Get updated session
	session, err = h.storage.GetExecutionSession(ctx, sessionID)
	if err != nil {
		jsonwriter.WriteInternalServerError(w, "Failed to get updated session")
		return
	}

	jsonwriter.Write(w, HeartbeatResponse{
		ExpiresAt:       session.ExpiresAt,
		MaxTTLExpiresAt: session.CreatedAt.Add(session.MaxTTL),
		RequestCount:    session.RequestCount,
	})
}

// ListSessionsHandler handles GET /api/execution-sessions
func (h *ExecutionHandlers) ListSessionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteMethodNotAllowed(w, "Method not allowed")
		return
	}

	ctx := r.Context()
	userEmail, ok := oauth.GetUserFromContext(ctx)
	if !ok {
		jsonwriter.WriteUnauthorized(w, "Unauthorized")
		return
	}

	isAdmin := h.adminConfig != nil && adminauth.IsAdmin(ctx, userEmail, h.adminConfig, h.storage)

	var sessions []*storage.ExecutionSession
	var err error

	if isAdmin && r.URL.Query().Get("all") == "true" {
		sessions, err = h.storage.ListAllExecutionSessions(ctx)
	} else {
		sessions, err = h.storage.ListUserExecutionSessions(ctx, userEmail)
	}

	if err != nil {
		log.LogError("Failed to list sessions: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to list sessions")
		return
	}

	// Transform to response format
	response := make([]SessionInfo, 0, len(sessions))
	for _, s := range sessions {
		response = append(response, SessionInfo{
			SessionID:       s.SessionID,
			ExecutionID:     s.ExecutionID,
			User:            s.UserEmail,
			Service:         s.TargetService,
			CreatedAt:       s.CreatedAt,
			LastActivity:    s.LastHeartbeat,
			ExpiresAt:       s.ExpiresAt,
			MaxTTLExpiresAt: s.CreatedAt.Add(s.MaxTTL),
			RequestCount:    s.RequestCount,
			MaxRequests:     s.MaxRequests,
		})
	}

	jsonwriter.Write(w, response)
}

// DeleteSessionHandler handles DELETE /api/execution-session/{session_id}
func (h *ExecutionHandlers) DeleteSessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonwriter.WriteMethodNotAllowed(w, "Method not allowed")
		return
	}

	ctx := r.Context()
	sessionID := r.PathValue("session_id")

	// Get session
	session, err := h.storage.GetExecutionSession(ctx, sessionID)
	if err != nil {
		if err == storage.ErrSessionNotFound {
			jsonwriter.WriteNotFound(w, "Session not found")
		} else {
			jsonwriter.WriteInternalServerError(w, "Failed to get session")
		}
		return
	}

	// Verify user owns this session (or is admin)
	userEmail, ok := oauth.GetUserFromContext(ctx)
	isAdmin := h.adminConfig != nil && adminauth.IsAdmin(ctx, userEmail, h.adminConfig, h.storage)
	if !ok || (session.UserEmail != userEmail && !isAdmin) {
		jsonwriter.WriteForbidden(w, "Cannot delete another user's session")
		return
	}

	// Delete session
	err = h.storage.DeleteExecutionSession(ctx, sessionID)
	if err != nil {
		log.LogError("Failed to delete session: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to delete session")
		return
	}

	log.LogInfoWithFields("execution_handlers", "Deleted execution session", map[string]any{
		"session_id":   sessionID,
		"execution_id": session.ExecutionID,
		"user":         session.UserEmail,
		"service":      session.TargetService,
		"deleted_by":   userEmail,
	})

	jsonwriter.Write(w, map[string]string{
		"status":     "terminated",
		"session_id": sessionID,
	})
}

// generateSessionID generates a cryptographically random session ID
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sess_" + base64.URLEncoding.EncodeToString(b)[:22], nil
}
