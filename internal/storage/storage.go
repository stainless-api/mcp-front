package storage

import (
	"context"
	"errors"
	"time"

	"github.com/dgellow/mcp-front/internal/oauth"
)

var ErrUserTokenNotFound = errors.New("user token not found")
var ErrUserNotFound = errors.New("user not found")
var ErrSessionNotFound = errors.New("session not found")
var ErrClientNotFound = errors.New("client not found")
var ErrGrantNotFound = errors.New("grant not found")

type UserInfo struct {
	Email     string    `json:"email"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Enabled   bool      `json:"enabled"`
	IsAdmin   bool      `json:"is_admin"`
}

type TokenType string

const (
	TokenTypeManual TokenType = "manual"
	TokenTypeOAuth  TokenType = "oauth"
)

type OAuthTokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scopes       []string  `json:"scopes,omitempty"`
}

type StoredToken struct {
	Type      TokenType       `json:"type"`
	Value     string          `json:"value,omitempty"`
	OAuthData *OAuthTokenData `json:"oauth,omitempty"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type ActiveSession struct {
	SessionID  string    `json:"session_id"`
	UserEmail  string    `json:"user_email"`
	ServerName string    `json:"server_name"`
	Created    time.Time `json:"created"`
	LastActive time.Time `json:"last_active"`
}

type UserTokenStore interface {
	GetUserToken(ctx context.Context, userEmail, service string) (*StoredToken, error)
	SetUserToken(ctx context.Context, userEmail, service string, token *StoredToken) error
	DeleteUserToken(ctx context.Context, userEmail, service string) error
	ListUserServices(ctx context.Context, userEmail string) ([]string, error)
}

type Storage interface {
	// OAuth client management
	GetClient(ctx context.Context, clientID string) (*Client, error)
	CreateClient(ctx context.Context, clientID string, redirectURIs []string, scopes []string, issuer string) (*Client, error)
	CreateConfidentialClient(ctx context.Context, clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) (*Client, error)

	// Grant management (authorization codes)
	StoreGrant(ctx context.Context, code string, grant *oauth.Grant) error
	ConsumeGrant(ctx context.Context, code string) (*oauth.Grant, error)

	// User token storage
	UserTokenStore

	// User tracking
	UpsertUser(ctx context.Context, email string) error
	GetUser(ctx context.Context, email string) (*UserInfo, error)
	GetAllUsers(ctx context.Context) ([]UserInfo, error)
	UpdateUserStatus(ctx context.Context, email string, enabled bool) error
	DeleteUser(ctx context.Context, email string) error
	SetUserAdmin(ctx context.Context, email string, isAdmin bool) error

	// Session tracking
	TrackSession(ctx context.Context, session ActiveSession) error
	GetActiveSessions(ctx context.Context) ([]ActiveSession, error)
	RevokeSession(ctx context.Context, sessionID string) error
}
