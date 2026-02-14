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
	sessions        map[string]*ActiveSession
	sessionsMutex   sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		clients:    make(map[string]*Client),
		grants:     make(map[string]*oauth.Grant),
		userTokens: make(map[string]*StoredToken),
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

func (s *MemoryStorage) RevokeSession(ctx context.Context, sessionID string) error {
	s.sessionsMutex.Lock()
	defer s.sessionsMutex.Unlock()

	delete(s.sessions, sessionID)
	return nil
}
