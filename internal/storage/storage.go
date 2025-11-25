package storage

import (
	"context"
	"errors"
	"time"

	"github.com/ory/fosite"
	fosite_storage "github.com/ory/fosite/storage"
)

// ErrUserTokenNotFound is returned when a user token doesn't exist
var ErrUserTokenNotFound = errors.New("user token not found")

// ErrUserNotFound is returned when a user doesn't exist
var ErrUserNotFound = errors.New("user not found")

// ErrSessionNotFound is returned when a session doesn't exist
var ErrSessionNotFound = errors.New("session not found")

// UserInfo represents a user who has authenticated via OAuth
type UserInfo struct {
	Email     string    `json:"email"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Enabled   bool      `json:"enabled"`
	IsAdmin   bool      `json:"is_admin"`
}

// TokenType represents the type of stored token
type TokenType string

const (
	TokenTypeManual TokenType = "manual"
	TokenTypeOAuth  TokenType = "oauth"
)

// OAuthTokenData represents OAuth token metadata
type OAuthTokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
}

// StoredToken represents a token with its metadata
type StoredToken struct {
	Type      TokenType       `json:"type"`
	Value     string          `json:"value,omitempty"` // For manual tokens
	OAuthData *OAuthTokenData `json:"oauth,omitempty"` // For OAuth tokens
	UpdatedAt time.Time       `json:"updated_at"`
}

// ActiveSession represents an active MCP session
type ActiveSession struct {
	SessionID  string    `json:"session_id"`
	UserEmail  string    `json:"user_email"`
	ServerName string    `json:"server_name"`
	Created    time.Time `json:"created"`
	LastActive time.Time `json:"last_active"`
}

// ExecutionSession represents an execution proxy session with lifecycle management
type ExecutionSession struct {
	SessionID     string        `json:"session_id"`
	ExecutionID   string        `json:"execution_id"`   // For logging/tracing
	UserEmail     string        `json:"user_email"`
	TargetService string        `json:"target_service"`
	AllowedPaths  []string      `json:"allowed_paths"`
	CreatedAt     time.Time     `json:"created_at"`
	LastHeartbeat time.Time     `json:"last_heartbeat"`
	ExpiresAt     time.Time     `json:"expires_at"`      // LastHeartbeat + IdleTimeout
	IdleTimeout   time.Duration `json:"idle_timeout"`    // e.g., 30s
	MaxTTL        time.Duration `json:"max_ttl"`         // e.g., 15 min (absolute max)
	MaxRequests   int           `json:"max_requests"`    // e.g., 1000
	RequestCount  int           `json:"request_count"`
}

// IsExpired returns true if the session has expired
func (s *ExecutionSession) IsExpired() bool {
	now := time.Now()

	// Expired due to inactivity
	if now.After(s.ExpiresAt) {
		return true
	}

	// Expired due to absolute max TTL
	if now.After(s.CreatedAt.Add(s.MaxTTL)) {
		return true
	}

	// Expired due to request limit
	if s.MaxRequests > 0 && s.RequestCount >= s.MaxRequests {
		return true
	}

	return false
}

// TimeUntilExpiry returns the duration until the session expires
func (s *ExecutionSession) TimeUntilExpiry() time.Duration {
	now := time.Now()

	// Check inactivity expiration
	idleExpiry := s.ExpiresAt.Sub(now)

	// Check absolute TTL expiration
	absoluteExpiry := s.CreatedAt.Add(s.MaxTTL).Sub(now)

	// Return whichever comes first
	if idleExpiry < absoluteExpiry {
		return idleExpiry
	}
	return absoluteExpiry
}

// UserTokenStore defines methods for managing user tokens.
// This interface is used by handlers that need to access user-specific tokens
// for external services (e.g., Notion, GitHub).
type UserTokenStore interface {
	GetUserToken(ctx context.Context, userEmail, service string) (*StoredToken, error)
	SetUserToken(ctx context.Context, userEmail, service string, token *StoredToken) error
	DeleteUserToken(ctx context.Context, userEmail, service string) error
	ListUserServices(ctx context.Context, userEmail string) ([]string, error)
}

// ExecutionSessionStore defines methods for managing execution proxy sessions
type ExecutionSessionStore interface {
	CreateExecutionSession(ctx context.Context, session *ExecutionSession) error
	GetExecutionSession(ctx context.Context, sessionID string) (*ExecutionSession, error)
	UpdateExecutionSession(ctx context.Context, session *ExecutionSession) error
	DeleteExecutionSession(ctx context.Context, sessionID string) error
	RecordSessionActivity(ctx context.Context, sessionID string) error
	ListUserExecutionSessions(ctx context.Context, userEmail string) ([]*ExecutionSession, error)
	ListAllExecutionSessions(ctx context.Context) ([]*ExecutionSession, error)
	CleanupExpiredSessions(ctx context.Context) (int, error)
}

// Storage combines all storage capabilities needed by mcp-front
type Storage interface {
	// OAuth storage requirements
	fosite.Storage

	// OAuth state management
	StoreAuthorizeRequest(state string, req fosite.AuthorizeRequester)
	GetAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool)

	// OAuth client management
	CreateClient(clientID string, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient
	CreateConfidentialClient(clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient
	GetAllClients() map[string]fosite.Client
	GetMemoryStore() *fosite_storage.MemoryStore

	// User token storage
	UserTokenStore

	// Execution session storage
	ExecutionSessionStore

	// User tracking (upserted when users access MCP endpoints)
	UpsertUser(ctx context.Context, email string) error
	GetAllUsers(ctx context.Context) ([]UserInfo, error)
	UpdateUserStatus(ctx context.Context, email string, enabled bool) error
	DeleteUser(ctx context.Context, email string) error
	SetUserAdmin(ctx context.Context, email string, isAdmin bool) error

	// Session tracking
	TrackSession(ctx context.Context, session ActiveSession) error
	GetActiveSessions(ctx context.Context) ([]ActiveSession, error)
	RevokeSession(ctx context.Context, sessionID string) error
}
