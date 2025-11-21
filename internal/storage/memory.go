package storage

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/dgellow/mcp-front/internal/log"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// Ensure MemoryStorage implements required interfaces
var _ Storage = (*MemoryStorage)(nil)
var _ fosite.Storage = (*MemoryStorage)(nil)

// MemoryStorage is a simple storage layer - only stores and retrieves data
// It extends the MemoryStore with thread-safe client management
type MemoryStorage struct {
	*storage.MemoryStore
	stateCache      sync.Map                // map[string]fosite.AuthorizeRequester
	clientsMutex    sync.RWMutex            // For thread-safe client access
	userTokens      map[string]*StoredToken // map["email:service"] = token
	userTokensMutex sync.RWMutex
	users           map[string]*UserInfo // map[email] = UserInfo
	usersMutex      sync.RWMutex
	sessions        map[string]*ActiveSession // map[sessionID] = ActiveSession
	sessionsMutex   sync.RWMutex
}

// NewMemoryStorage creates a new storage instance
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		MemoryStore: storage.NewMemoryStore(),
		userTokens:  make(map[string]*StoredToken),
		users:       make(map[string]*UserInfo),
		sessions:    make(map[string]*ActiveSession),
	}
}

// StoreAuthorizeRequest stores an authorize request with state
func (s *MemoryStorage) StoreAuthorizeRequest(state string, req fosite.AuthorizeRequester) {
	s.stateCache.Store(state, req)
}

// GetAuthorizeRequest retrieves an authorize request by state (one-time use)
func (s *MemoryStorage) GetAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool) {
	if req, ok := s.stateCache.Load(state); ok {
		s.stateCache.Delete(state) // One-time use
		return req.(fosite.AuthorizeRequester), true
	}
	return nil, false
}

// GetClient overrides the MemoryStore's GetClient to use our mutex
func (s *MemoryStorage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.MemoryStore.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

// CreateClient creates a dynamic client and stores it thread-safely
func (s *MemoryStorage) CreateClient(clientID string, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient {
	// Create as public client (no secret) since MCP Inspector is a public client
	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        nil, // Public client - no secret
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        true, // Mark as public client
	}

	// Thread-safe client storage
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	clientCount := len(s.MemoryStore.Clients)
	s.clientsMutex.Unlock()

	log.Logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client
}

// CreateConfidentialClient creates a dynamic confidential client with a secret and stores it thread-safely
func (s *MemoryStorage) CreateConfidentialClient(clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient {
	// Create as confidential client (with secret)
	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret, // Already hashed
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        false, // Mark as confidential client
	}

	// Thread-safe client storage
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	clientCount := len(s.MemoryStore.Clients)
	s.clientsMutex.Unlock()

	log.Logf("Created confidential client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client
}

// GetAllClients returns all clients thread-safely (for debugging)
func (s *MemoryStorage) GetAllClients() map[string]fosite.Client {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	clients := make(map[string]fosite.Client, len(s.MemoryStore.Clients)) // Copy to avoid races
	maps.Copy(clients, s.MemoryStore.Clients)
	return clients
}

// GetMemoryStore returns the underlying MemoryStore for fosite
func (s *MemoryStorage) GetMemoryStore() *storage.MemoryStore {
	return s.MemoryStore
}

// User token methods

// makeUserTokenKey creates a key for the user token map
func (s *MemoryStorage) makeUserTokenKey(userEmail, service string) string {
	return userEmail + ":" + service
}

// GetUserToken retrieves a user's token for a specific service
func (s *MemoryStorage) GetUserToken(ctx context.Context, userEmail, service string) (*StoredToken, error) {
	s.userTokensMutex.RLock()
	defer s.userTokensMutex.RUnlock()

	key := s.makeUserTokenKey(userEmail, service)
	token, exists := s.userTokens[key]
	if !exists {
		return nil, ErrUserTokenNotFound
	}
	return token, nil
}

// SetUserToken stores or updates a user's token for a specific service
func (s *MemoryStorage) SetUserToken(ctx context.Context, userEmail, service string, token *StoredToken) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	s.userTokensMutex.Lock()
	defer s.userTokensMutex.Unlock()

	key := s.makeUserTokenKey(userEmail, service)
	s.userTokens[key] = token
	return nil
}

// DeleteUserToken removes a user's token for a specific service
func (s *MemoryStorage) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	s.userTokensMutex.Lock()
	defer s.userTokensMutex.Unlock()

	key := s.makeUserTokenKey(userEmail, service)
	delete(s.userTokens, key)
	return nil
}

// ListUserServices returns all services for which a user has configured tokens
func (s *MemoryStorage) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	s.userTokensMutex.RLock()
	defer s.userTokensMutex.RUnlock()

	var services []string
	prefix := userEmail + ":"
	for key := range s.userTokens {
		if after, ok := strings.CutPrefix(key, prefix); ok {
			service := after
			services = append(services, service)
		}
	}
	return services, nil
}

// UpsertUser creates or updates a user's last seen time
func (s *MemoryStorage) UpsertUser(ctx context.Context, email string) error {
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()

	if user, exists := s.users[email]; exists {
		user.LastSeen = time.Now()
	} else {
		s.users[email] = &UserInfo{
			Email:     email,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Enabled:   true,
			IsAdmin:   false,
		}
	}
	return nil
}

// GetAllUsers returns all users
func (s *MemoryStorage) GetAllUsers(ctx context.Context) ([]UserInfo, error) {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	users := make([]UserInfo, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, *user)
	}
	return users, nil
}

// UpdateUserStatus updates a user's enabled status
func (s *MemoryStorage) UpdateUserStatus(ctx context.Context, email string, enabled bool) error {
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()

	user, exists := s.users[email]
	if !exists {
		return ErrUserNotFound
	}
	// Create a copy to avoid modifying the struct directly
	userCopy := *user
	userCopy.Enabled = enabled
	s.users[email] = &userCopy
	return nil
}

// DeleteUser removes a user from storage
func (s *MemoryStorage) DeleteUser(ctx context.Context, email string) error {
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()

	delete(s.users, email)

	// Also delete all user tokens
	s.userTokensMutex.Lock()
	defer s.userTokensMutex.Unlock()

	prefix := email + ":"
	for key := range s.userTokens {
		if strings.HasPrefix(key, prefix) {
			delete(s.userTokens, key)
		}
	}

	return nil
}

// SetUserAdmin updates a user's admin status
func (s *MemoryStorage) SetUserAdmin(ctx context.Context, email string, isAdmin bool) error {
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()

	user, exists := s.users[email]
	if !exists {
		return ErrUserNotFound
	}
	// Create a copy to avoid modifying the struct directly
	userCopy := *user
	userCopy.IsAdmin = isAdmin
	s.users[email] = &userCopy
	return nil
}

// TrackSession creates or updates a session
func (s *MemoryStorage) TrackSession(ctx context.Context, session ActiveSession) error {
	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	if existing, exists := s.sessions[session.SessionID]; exists {
		existing.LastActive = time.Now()
	} else {
		sessionCopy := session
		sessionCopy.Created = time.Now()
		sessionCopy.LastActive = time.Now()
		s.sessions[session.SessionID] = &sessionCopy
	}
	return nil
}

// GetActiveSessions returns all active sessions
func (s *MemoryStorage) GetActiveSessions(ctx context.Context) ([]ActiveSession, error) {
	s.sessionsMutex.RLock()
	defer s.sessionsMutex.RUnlock()

	sessions := make([]ActiveSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, *session)
	}
	return sessions, nil
}

// RevokeSession removes a session
func (s *MemoryStorage) RevokeSession(ctx context.Context, sessionID string) error {
	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	delete(s.sessions, sessionID)
	return nil
}
