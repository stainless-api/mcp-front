package storage

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
)

var _ Storage = (*MemoryStorage)(nil)

type MemoryStorage struct {
	clients         map[string]*Client
	clientsMutex    sync.RWMutex
	grants          map[string]*oauth.Grant
	grantsMutex     sync.Mutex
	userTokens      map[string]*StoredToken
	userTokensMutex sync.RWMutex
	users           map[string]*UserInfo
	usersMutex      sync.RWMutex
	sessions        map[string]*ActiveSession
	sessionsMutex   sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		clients:    make(map[string]*Client),
		grants:     make(map[string]*oauth.Grant),
		userTokens: make(map[string]*StoredToken),
		users:      make(map[string]*UserInfo),
		sessions:   make(map[string]*ActiveSession),
	}
}

func (s *MemoryStorage) GetClient(_ context.Context, id string) (*Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, ErrClientNotFound
	}
	return client.clone(), nil
}

func (s *MemoryStorage) CreateClient(ctx context.Context, clientID string, redirectURIs []string, scopes []string, issuer string) (*Client, error) {
	client := &Client{
		ID:            clientID,
		Secret:        nil,
		RedirectURIs:  slices.Clone(redirectURIs),
		Scopes:        slices.Clone(scopes),
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        true,
		CreatedAt:     time.Now().Unix(),
	}

	s.clientsMutex.Lock()
	s.clients[clientID] = client
	clientCount := len(s.clients)
	s.clientsMutex.Unlock()

	log.Logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client.clone(), nil
}

func (s *MemoryStorage) CreateConfidentialClient(ctx context.Context, clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) (*Client, error) {
	client := &Client{
		ID:            clientID,
		Secret:        slices.Clone(hashedSecret),
		RedirectURIs:  slices.Clone(redirectURIs),
		Scopes:        slices.Clone(scopes),
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        false,
		CreatedAt:     time.Now().Unix(),
	}

	s.clientsMutex.Lock()
	s.clients[clientID] = client
	clientCount := len(s.clients)
	s.clientsMutex.Unlock()

	log.Logf("Created confidential client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client.clone(), nil
}

func (s *MemoryStorage) StoreGrant(ctx context.Context, code string, grant *oauth.Grant) error {
	s.grantsMutex.Lock()
	defer s.grantsMutex.Unlock()
	s.grants[code] = grant
	return nil
}

func (s *MemoryStorage) ConsumeGrant(ctx context.Context, code string) (*oauth.Grant, error) {
	s.grantsMutex.Lock()
	defer s.grantsMutex.Unlock()

	grant, ok := s.grants[code]
	if !ok {
		return nil, ErrGrantNotFound
	}
	delete(s.grants, code)
	return grant, nil
}

// User token methods

func (s *MemoryStorage) makeUserTokenKey(userEmail, service string) string {
	return userEmail + ":" + service
}

func (s *MemoryStorage) GetUserToken(ctx context.Context, userEmail, service string) (*StoredToken, error) {
	s.userTokensMutex.RLock()
	defer s.userTokensMutex.RUnlock()

	key := s.makeUserTokenKey(userEmail, service)
	token, exists := s.userTokens[key]
	if !exists {
		return nil, ErrUserTokenNotFound
	}
	tokenCopy := *token
	return &tokenCopy, nil
}

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

func (s *MemoryStorage) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	s.userTokensMutex.Lock()
	defer s.userTokensMutex.Unlock()

	key := s.makeUserTokenKey(userEmail, service)
	delete(s.userTokens, key)
	return nil
}

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

func (s *MemoryStorage) GetUser(ctx context.Context, email string) (*UserInfo, error) {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	user, exists := s.users[email]
	if !exists {
		return nil, ErrUserNotFound
	}
	userCopy := *user
	return &userCopy, nil
}

func (s *MemoryStorage) GetAllUsers(ctx context.Context) ([]UserInfo, error) {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	users := make([]UserInfo, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, *user)
	}
	return users, nil
}

func (s *MemoryStorage) UpdateUserStatus(ctx context.Context, email string, enabled bool) error {
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()

	user, exists := s.users[email]
	if !exists {
		return ErrUserNotFound
	}
	userCopy := *user
	userCopy.Enabled = enabled
	s.users[email] = &userCopy
	return nil
}

func (s *MemoryStorage) DeleteUser(ctx context.Context, email string) error {
	s.userTokensMutex.Lock()
	prefix := email + ":"
	for key := range s.userTokens {
		if strings.HasPrefix(key, prefix) {
			delete(s.userTokens, key)
		}
	}
	s.userTokensMutex.Unlock()

	s.sessionsMutex.Lock()
	for id, sess := range s.sessions {
		if sess.UserEmail == email {
			delete(s.sessions, id)
		}
	}
	s.sessionsMutex.Unlock()

	s.usersMutex.Lock()
	delete(s.users, email)
	s.usersMutex.Unlock()

	return nil
}

func (s *MemoryStorage) SetUserAdmin(ctx context.Context, email string, isAdmin bool) error {
	s.usersMutex.Lock()
	defer s.usersMutex.Unlock()

	user, exists := s.users[email]
	if !exists {
		return ErrUserNotFound
	}
	userCopy := *user
	userCopy.IsAdmin = isAdmin
	s.users[email] = &userCopy
	return nil
}

func (s *MemoryStorage) TrackSession(ctx context.Context, session ActiveSession) error {
	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	now := time.Now()
	if existing, exists := s.sessions[session.SessionID]; exists {
		existing.LastActive = now
	} else {
		sessionCopy := session
		if sessionCopy.Created.IsZero() {
			sessionCopy.Created = now
		}
		sessionCopy.LastActive = now
		s.sessions[session.SessionID] = &sessionCopy
	}
	return nil
}

func (s *MemoryStorage) GetActiveSessions(ctx context.Context) ([]ActiveSession, error) {
	s.sessionsMutex.RLock()
	defer s.sessionsMutex.RUnlock()

	sessions := make([]ActiveSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, *session)
	}
	return sessions, nil
}

func (s *MemoryStorage) RevokeSession(ctx context.Context, sessionID string) error {
	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	delete(s.sessions, sessionID)
	return nil
}
