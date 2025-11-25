package storage

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FirestoreStorage implements OAuth client storage using Google Cloud Firestore.
//
// Error handling strategy:
// - Read operations: Return errors (data must be available for auth to work)
// - Write operations: Log and continue (fallback to memory cache is acceptable)
//
// This allows the system to function even if Firestore has transient issues,
// while ensuring that missing data causes explicit failures.
type FirestoreStorage struct {
	*storage.MemoryStore
	client          *firestore.Client
	stateCache      sync.Map     // In-memory cache for authorize requests (short-lived)
	clientsMutex    sync.RWMutex // For thread-safe client access
	projectID       string
	collection      string
	encryptor       crypto.Encryptor
	tokenCollection string // Collection for user tokens
}

// Ensure FirestoreStorage implements Storage interface
var _ Storage = (*FirestoreStorage)(nil)
var _ fosite.Storage = (*FirestoreStorage)(nil)

// UserTokenDoc represents a user token document in Firestore
type UserTokenDoc struct {
	UserEmail string          `firestore:"user_email"`
	Service   string          `firestore:"service"`
	Type      TokenType       `firestore:"type"`
	Value     string          `firestore:"value,omitempty"`      // Encrypted manual token
	OAuthData *OAuthTokenData `firestore:"oauth_data,omitempty"` // OAuth metadata (tokens encrypted)
	UpdatedAt time.Time       `firestore:"updated_at"`
}

// OAuthClientEntity represents the structure stored in Firestore
type OAuthClientEntity struct {
	ID            string   `firestore:"id"`
	Secret        *string  `firestore:"secret,omitempty"` // nil for public clients
	RedirectURIs  []string `firestore:"redirect_uris"`
	Scopes        []string `firestore:"scopes"`
	GrantTypes    []string `firestore:"grant_types"`
	ResponseTypes []string `firestore:"response_types"`
	Audience      []string `firestore:"audience"`
	Public        bool     `firestore:"public"`
	CreatedAt     int64    `firestore:"created_at"`
}

// ToFositeClient converts the Firestore entity to a fosite client
func (e *OAuthClientEntity) ToFositeClient(encryptor crypto.Encryptor) (*fosite.DefaultClient, error) {
	var secret []byte
	if e.Secret != nil {
		// Decrypt the secret
		decrypted, err := encryptor.Decrypt(*e.Secret)
		if err != nil {
			return nil, fmt.Errorf("decrypting client secret: %w", err)
		}
		secret = []byte(decrypted)
	}

	return &fosite.DefaultClient{
		ID:            e.ID,
		Secret:        secret,
		RedirectURIs:  e.RedirectURIs,
		Scopes:        e.Scopes,
		GrantTypes:    e.GrantTypes,
		ResponseTypes: e.ResponseTypes,
		Audience:      e.Audience,
		Public:        e.Public,
	}, nil
}

// FromFositeClient converts a fosite client to a Firestore entity
func FromFositeClient(client fosite.Client, encryptor crypto.Encryptor, createdAt int64) (*OAuthClientEntity, error) {
	var secret *string
	if clientSecret := client.GetHashedSecret(); len(clientSecret) > 0 {
		// Encrypt the secret before storing
		encrypted, err := encryptor.Encrypt(string(clientSecret))
		if err != nil {
			return nil, fmt.Errorf("encrypting client secret: %w", err)
		}
		secret = &encrypted
	}

	return &OAuthClientEntity{
		ID:            client.GetID(),
		Secret:        secret,
		RedirectURIs:  client.GetRedirectURIs(),
		Scopes:        client.GetScopes(),
		GrantTypes:    client.GetGrantTypes(),
		ResponseTypes: client.GetResponseTypes(),
		Audience:      client.GetAudience(),
		Public:        client.IsPublic(),
		CreatedAt:     createdAt,
	}, nil
}

// NewFirestoreStorage creates a new Firestore storage instance
func NewFirestoreStorage(ctx context.Context, projectID, database, collection string, encryptor crypto.Encryptor) (*FirestoreStorage, error) {
	if encryptor == nil {
		return nil, fmt.Errorf("encryptor is required")
	}

	// Validate required parameters
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if collection == "" {
		return nil, fmt.Errorf("collection is required")
	}

	var client *firestore.Client
	var err error

	// Firestore client with custom database
	if database != "" && database != "(default)" {
		client, err = firestore.NewClientWithDatabase(ctx, projectID, database)
	} else {
		client, err = firestore.NewClient(ctx, projectID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create Firestore client: %w", err)
	}

	storage := &FirestoreStorage{
		MemoryStore:     storage.NewMemoryStore(),
		client:          client,
		projectID:       projectID,
		collection:      collection,
		encryptor:       encryptor,
		tokenCollection: "mcp_front_user_tokens",
	}

	// Load existing clients from Firestore into memory for fast access
	if err := storage.loadClientsFromFirestore(ctx); err != nil {
		log.LogError("Failed to load clients from Firestore: %v", err)
		// Don't fail startup, just log the error
	}

	return storage, nil
}

// loadClientsFromFirestore loads all OAuth clients from Firestore into memory
func (s *FirestoreStorage) loadClientsFromFirestore(ctx context.Context) error {
	iter := s.client.Collection(s.collection).Documents(ctx)
	defer iter.Stop()

	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	loadedCount := 0
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("error iterating Firestore documents: %w", err)
		}

		var entity OAuthClientEntity
		if err := doc.DataTo(&entity); err != nil {
			log.LogError("Failed to unmarshal client from Firestore (client_id: %s): %v", doc.Ref.ID, err)
			continue
		}

		// Store in memory for fast access
		client, err := entity.ToFositeClient(s.encryptor)
		if err != nil {
			log.LogError("Failed to decrypt client secret (client_id: %s): %v", entity.ID, err)
			continue
		}
		s.MemoryStore.Clients[entity.ID] = client
		loadedCount++
	}

	log.Logf("Loaded %d OAuth clients from Firestore", loadedCount)
	return nil
}

// StoreAuthorizeRequest stores an authorize request with state (in memory only - short-lived)
func (s *FirestoreStorage) StoreAuthorizeRequest(state string, req fosite.AuthorizeRequester) {
	s.stateCache.Store(state, req)
}

// GetAuthorizeRequest retrieves an authorize request by state (one-time use)
func (s *FirestoreStorage) GetAuthorizeRequest(state string) (fosite.AuthorizeRequester, bool) {
	if req, ok := s.stateCache.Load(state); ok {
		s.stateCache.Delete(state) // One-time use
		return req.(fosite.AuthorizeRequester), true
	}
	return nil, false
}

// GetClient retrieves a client from memory cache, loading from Firestore on miss.
// Concurrent cache misses may load the same client multiple times from Firestore.
// This is acceptable because: (1) clients are loaded once at startup via loadAllClients,
// so misses only occur for newly registered clients, and (2) duplicate Firestore reads
// are safe (idempotent) and cost-negligible at mcp-front's scale.
func (s *FirestoreStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	s.clientsMutex.RLock()
	cl, ok := s.MemoryStore.Clients[id]
	s.clientsMutex.RUnlock()

	if ok {
		return cl, nil
	}

	// Cache miss - load from Firestore
	// Multiple threads might load simultaneously, but this is rare and safe
	client, err := s.loadClientFromFirestore(ctx, id)
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	return client, nil
}

// loadClientFromFirestore loads a single client from Firestore
func (s *FirestoreStorage) loadClientFromFirestore(ctx context.Context, clientID string) (fosite.Client, error) {
	doc, err := s.client.Collection(s.collection).Doc(clientID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get client from Firestore: %w", err)
	}

	var entity OAuthClientEntity
	if err := doc.DataTo(&entity); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client: %w", err)
	}

	client, err := entity.ToFositeClient(s.encryptor)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	// Store in memory for future fast access
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	s.clientsMutex.Unlock()

	return client, nil
}

// CreateClient creates a dynamic client and stores it in both memory and Firestore
func (s *FirestoreStorage) CreateClient(clientID string, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient {
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

	// Store in Firestore
	ctx := context.Background()
	entity, err := FromFositeClient(client, s.encryptor, time.Now().Unix())
	if err != nil {
		log.LogError("Failed to encrypt client for Firestore (client_id: %s): %v", clientID, err)
		// Continue with in-memory storage even if encryption fails
	} else {
		_, err := s.client.Collection(s.collection).Doc(clientID).Set(ctx, entity)
		if err != nil {
			log.LogError("Failed to store client in Firestore (client_id: %s): %v", clientID, err)
			// Continue with in-memory storage even if Firestore fails
		} else {
			log.Logf("Stored client %s in Firestore", clientID)
		}
	}

	// Thread-safe client storage in memory
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	clientCount := len(s.MemoryStore.Clients)
	s.clientsMutex.Unlock()

	log.Logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client
}

// CreateConfidentialClient creates a dynamic confidential client with a secret and stores it in both memory and Firestore
func (s *FirestoreStorage) CreateConfidentialClient(clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) *fosite.DefaultClient {
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

	// Store in Firestore
	ctx := context.Background()
	entity, err := FromFositeClient(client, s.encryptor, time.Now().Unix())
	if err != nil {
		log.LogError("Failed to encrypt client for Firestore (client_id: %s): %v", clientID, err)
		// Continue with in-memory storage even if encryption fails
	} else {
		_, err := s.client.Collection(s.collection).Doc(clientID).Set(ctx, entity)
		if err != nil {
			log.LogError("Failed to store client in Firestore (client_id: %s): %v", clientID, err)
			// Continue with in-memory storage even if Firestore fails
		} else {
			log.Logf("Stored confidential client %s in Firestore", clientID)
		}
	}

	// Thread-safe client storage in memory
	s.clientsMutex.Lock()
	s.MemoryStore.Clients[clientID] = client
	clientCount := len(s.MemoryStore.Clients)
	s.clientsMutex.Unlock()

	log.Logf("Created confidential client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client
}

// GetAllClients returns all clients thread-safely (for debugging)
func (s *FirestoreStorage) GetAllClients() map[string]fosite.Client {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	// Create a copy to avoid race conditions
	clients := make(map[string]fosite.Client, len(s.MemoryStore.Clients))
	maps.Copy(clients, s.MemoryStore.Clients)
	return clients
}

// GetMemoryStore returns the underlying MemoryStore for fosite
func (s *FirestoreStorage) GetMemoryStore() *storage.MemoryStore {
	return s.MemoryStore
}

// Close closes the Firestore client
func (s *FirestoreStorage) Close() error {
	return s.client.Close()
}

// User token methods

// makeUserTokenDocID creates a document ID for a user token
func (s *FirestoreStorage) makeUserTokenDocID(userEmail, service string) string {
	return userEmail + "__" + service
}

// GetUserToken retrieves a user's token for a specific service
func (s *FirestoreStorage) GetUserToken(ctx context.Context, userEmail, service string) (*StoredToken, error) {
	docID := s.makeUserTokenDocID(userEmail, service)
	doc, err := s.client.Collection(s.tokenCollection).Doc(docID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrUserTokenNotFound
		}
		return nil, fmt.Errorf("failed to get token from Firestore: %w", err)
	}

	var tokenDoc UserTokenDoc
	if err := doc.DataTo(&tokenDoc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	// Build StoredToken
	storedToken := &StoredToken{
		Type:      tokenDoc.Type,
		UpdatedAt: tokenDoc.UpdatedAt,
	}

	// Decrypt based on type
	switch tokenDoc.Type {
	case TokenTypeManual:
		if tokenDoc.Value != "" {
			decrypted, err := s.encryptor.Decrypt(tokenDoc.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt manual token: %w", err)
			}
			storedToken.Value = decrypted
		}
	case TokenTypeOAuth:
		if tokenDoc.OAuthData != nil {
			// Decrypt OAuth tokens
			decryptedAccess, err := s.encryptor.Decrypt(tokenDoc.OAuthData.AccessToken)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt access token: %w", err)
			}

			oauthData := &OAuthTokenData{
				AccessToken: decryptedAccess,
				TokenType:   tokenDoc.OAuthData.TokenType,
				ExpiresAt:   tokenDoc.OAuthData.ExpiresAt,
				Scopes:      tokenDoc.OAuthData.Scopes,
			}

			if tokenDoc.OAuthData.RefreshToken != "" {
				decryptedRefresh, err := s.encryptor.Decrypt(tokenDoc.OAuthData.RefreshToken)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
				}
				oauthData.RefreshToken = decryptedRefresh
			}

			storedToken.OAuthData = oauthData
		}
	}

	return storedToken, nil
}

// SetUserToken stores or updates a user's token for a specific service
func (s *FirestoreStorage) SetUserToken(ctx context.Context, userEmail, service string, token *StoredToken) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	docID := s.makeUserTokenDocID(userEmail, service)
	tokenDoc := UserTokenDoc{
		UserEmail: userEmail,
		Service:   service,
		Type:      token.Type,
		UpdatedAt: time.Now(),
	}

	// Encrypt based on type
	switch token.Type {
	case TokenTypeManual:
		if token.Value != "" {
			encrypted, err := s.encryptor.Encrypt(token.Value)
			if err != nil {
				return fmt.Errorf("failed to encrypt manual token: %w", err)
			}
			tokenDoc.Value = encrypted
		}
	case TokenTypeOAuth:
		if token.OAuthData != nil {
			// Encrypt OAuth tokens
			encryptedAccess, err := s.encryptor.Encrypt(token.OAuthData.AccessToken)
			if err != nil {
				return fmt.Errorf("failed to encrypt access token: %w", err)
			}

			oauthData := &OAuthTokenData{
				AccessToken: encryptedAccess,
				TokenType:   token.OAuthData.TokenType,
				ExpiresAt:   token.OAuthData.ExpiresAt,
				Scopes:      token.OAuthData.Scopes,
			}

			if token.OAuthData.RefreshToken != "" {
				encryptedRefresh, err := s.encryptor.Encrypt(token.OAuthData.RefreshToken)
				if err != nil {
					return fmt.Errorf("failed to encrypt refresh token: %w", err)
				}
				oauthData.RefreshToken = encryptedRefresh
			}

			tokenDoc.OAuthData = oauthData
		}
	default:
		return fmt.Errorf("unknown token type: %s", token.Type)
	}

	_, err := s.client.Collection(s.tokenCollection).Doc(docID).Set(ctx, tokenDoc)
	if err != nil {
		return fmt.Errorf("failed to store token in Firestore: %w", err)
	}

	return nil
}

// DeleteUserToken removes a user's token for a specific service
func (s *FirestoreStorage) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	docID := s.makeUserTokenDocID(userEmail, service)
	_, err := s.client.Collection(s.tokenCollection).Doc(docID).Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete token from Firestore: %w", err)
	}
	return nil
}

// ListUserServices returns all services for which a user has configured tokens
func (s *FirestoreStorage) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	iter := s.client.Collection(s.tokenCollection).Where("user_email", "==", userEmail).Documents(ctx)
	defer iter.Stop()

	var services []string
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate user tokens: %w", err)
		}

		var tokenDoc UserTokenDoc
		if err := doc.DataTo(&tokenDoc); err != nil {
			// Log error but continue with other tokens
			log.LogError("Failed to unmarshal user token: %v", err)
			continue
		}

		services = append(services, tokenDoc.Service)
	}

	return services, nil
}

// UserDoc represents a user document in Firestore
type UserDoc struct {
	Email     string    `firestore:"email"`
	FirstSeen time.Time `firestore:"first_seen"`
	LastSeen  time.Time `firestore:"last_seen"`
	Enabled   bool      `firestore:"enabled"`
	IsAdmin   bool      `firestore:"is_admin"`
}

// SessionDoc represents a session document in Firestore
type SessionDoc struct {
	SessionID  string    `firestore:"session_id"`
	UserEmail  string    `firestore:"user_email"`
	ServerName string    `firestore:"server_name"`
	Created    time.Time `firestore:"created"`
	LastActive time.Time `firestore:"last_active"`
}

// UpsertUser creates or updates a user's last seen time
func (s *FirestoreStorage) UpsertUser(ctx context.Context, email string) error {
	userDoc := UserDoc{
		Email:    email,
		LastSeen: time.Now(),
	}

	// Try to get existing user first
	doc, err := s.client.Collection("mcp_front_users").Doc(email).Get(ctx)
	if err == nil {
		// User exists, update LastSeen
		_, err = doc.Ref.Update(ctx, []firestore.Update{
			{Path: "last_seen", Value: time.Now()},
		})
		return err
	}

	// User doesn't exist, create new
	if status.Code(err) == codes.NotFound {
		userDoc.FirstSeen = time.Now()
		userDoc.Enabled = true
		userDoc.IsAdmin = false
		_, err = s.client.Collection("mcp_front_users").Doc(email).Set(ctx, userDoc)
		return err
	}

	return err
}

// GetAllUsers returns all users
func (s *FirestoreStorage) GetAllUsers(ctx context.Context) ([]UserInfo, error) {
	iter := s.client.Collection("mcp_front_users").Documents(ctx)
	defer iter.Stop()

	var users []UserInfo
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate users: %w", err)
		}

		var userDoc UserDoc
		if err := doc.DataTo(&userDoc); err != nil {
			log.LogError("Failed to unmarshal user: %v", err)
			continue
		}

		users = append(users, UserInfo(userDoc))
	}

	return users, nil
}

// UpdateUserStatus updates a user's enabled status
func (s *FirestoreStorage) UpdateUserStatus(ctx context.Context, email string, enabled bool) error {
	_, err := s.client.Collection("mcp_front_users").Doc(email).Update(ctx, []firestore.Update{
		{Path: "enabled", Value: enabled},
	})
	if status.Code(err) == codes.NotFound {
		return ErrUserNotFound
	}
	return err
}

// DeleteUser removes a user from storage
func (s *FirestoreStorage) DeleteUser(ctx context.Context, email string) error {
	// Delete user document
	_, err := s.client.Collection("mcp_front_users").Doc(email).Delete(ctx)
	if err != nil && status.Code(err) != codes.NotFound {
		return err
	}

	// Also delete all user tokens
	iter := s.client.Collection(s.tokenCollection).Where("user_email", "==", email).Documents(ctx)
	defer iter.Stop()

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.LogError("Failed to iterate user tokens for deletion: %v", err)
			continue
		}

		_, err = doc.Ref.Delete(ctx)
		if err != nil {
			log.LogError("Failed to delete user token: %v", err)
		}
	}

	return nil
}

// SetUserAdmin updates a user's admin status
func (s *FirestoreStorage) SetUserAdmin(ctx context.Context, email string, isAdmin bool) error {
	_, err := s.client.Collection("mcp_front_users").Doc(email).Update(ctx, []firestore.Update{
		{Path: "is_admin", Value: isAdmin},
	})
	if status.Code(err) == codes.NotFound {
		return ErrUserNotFound
	}
	return err
}

// TrackSession creates or updates a session
func (s *FirestoreStorage) TrackSession(ctx context.Context, session ActiveSession) error {
	sessionDoc := SessionDoc{
		SessionID:  session.SessionID,
		UserEmail:  session.UserEmail,
		ServerName: session.ServerName,
		Created:    session.Created,
		LastActive: time.Now(),
	}

	// Check if session exists
	doc, err := s.client.Collection("mcp_front_sessions").Doc(session.SessionID).Get(ctx)
	if err == nil {
		// Session exists, update LastActive
		_, err = doc.Ref.Update(ctx, []firestore.Update{
			{Path: "last_active", Value: time.Now()},
		})
		return err
	}

	// Session doesn't exist, create new
	if status.Code(err) == codes.NotFound {
		sessionDoc.Created = time.Now()
		_, err = s.client.Collection("mcp_front_sessions").Doc(session.SessionID).Set(ctx, sessionDoc)
		return err
	}

	return err
}

// GetActiveSessions returns all active sessions
func (s *FirestoreStorage) GetActiveSessions(ctx context.Context) ([]ActiveSession, error) {
	iter := s.client.Collection("mcp_front_sessions").Documents(ctx)
	defer iter.Stop()

	var sessions []ActiveSession
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate sessions: %w", err)
		}

		var sessionDoc SessionDoc
		if err := doc.DataTo(&sessionDoc); err != nil {
			log.LogError("Failed to unmarshal session: %v", err)
			continue
		}

		sessions = append(sessions, ActiveSession(sessionDoc))
	}

	return sessions, nil
}

// RevokeSession removes a session
func (s *FirestoreStorage) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := s.client.Collection("mcp_front_sessions").Doc(sessionID).Delete(ctx)
	if err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	return nil
}

// ExecutionSession storage implementation

// ExecutionSessionDoc represents an execution session document in Firestore
type ExecutionSessionDoc struct {
	SessionID     string   `firestore:"session_id"`
	ExecutionID   string   `firestore:"execution_id"`
	UserEmail     string   `firestore:"user_email"`
	TargetService string   `firestore:"target_service"`
	AllowedPaths  []string `firestore:"allowed_paths"`
	CreatedAt     int64    `firestore:"created_at"`      // Unix timestamp
	LastHeartbeat int64    `firestore:"last_heartbeat"`  // Unix timestamp
	ExpiresAt     int64    `firestore:"expires_at"`      // Unix timestamp
	IdleTimeout   int64    `firestore:"idle_timeout"`    // Seconds
	MaxTTL        int64    `firestore:"max_ttl"`         // Seconds
	MaxRequests   int      `firestore:"max_requests"`
	RequestCount  int      `firestore:"request_count"`
}

// ToExecutionSession converts Firestore document to ExecutionSession
func (d *ExecutionSessionDoc) ToExecutionSession() *ExecutionSession {
	return &ExecutionSession{
		SessionID:     d.SessionID,
		ExecutionID:   d.ExecutionID,
		UserEmail:     d.UserEmail,
		TargetService: d.TargetService,
		AllowedPaths:  d.AllowedPaths,
		CreatedAt:     time.Unix(d.CreatedAt, 0),
		LastHeartbeat: time.Unix(d.LastHeartbeat, 0),
		ExpiresAt:     time.Unix(d.ExpiresAt, 0),
		IdleTimeout:   time.Duration(d.IdleTimeout) * time.Second,
		MaxTTL:        time.Duration(d.MaxTTL) * time.Second,
		MaxRequests:   d.MaxRequests,
		RequestCount:  d.RequestCount,
	}
}

// FromExecutionSession converts ExecutionSession to Firestore document
func FromExecutionSession(s *ExecutionSession) *ExecutionSessionDoc {
	return &ExecutionSessionDoc{
		SessionID:     s.SessionID,
		ExecutionID:   s.ExecutionID,
		UserEmail:     s.UserEmail,
		TargetService: s.TargetService,
		AllowedPaths:  s.AllowedPaths,
		CreatedAt:     s.CreatedAt.Unix(),
		LastHeartbeat: s.LastHeartbeat.Unix(),
		ExpiresAt:     s.ExpiresAt.Unix(),
		IdleTimeout:   int64(s.IdleTimeout.Seconds()),
		MaxTTL:        int64(s.MaxTTL.Seconds()),
		MaxRequests:   s.MaxRequests,
		RequestCount:  s.RequestCount,
	}
}

// CreateExecutionSession creates a new execution session in Firestore
func (s *FirestoreStorage) CreateExecutionSession(ctx context.Context, session *ExecutionSession) error {
	doc := FromExecutionSession(session)

	// Check if session already exists
	_, err := s.client.Collection("mcp_front_execution_sessions").Doc(session.SessionID).Get(ctx)
	if err == nil {
		return fmt.Errorf("session %s already exists", session.SessionID)
	}
	if status.Code(err) != codes.NotFound {
		return fmt.Errorf("failed to check session existence: %w", err)
	}

	// Create session document
	_, err = s.client.Collection("mcp_front_execution_sessions").Doc(session.SessionID).Set(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetExecutionSession retrieves an execution session from Firestore
func (s *FirestoreStorage) GetExecutionSession(ctx context.Context, sessionID string) (*ExecutionSession, error) {
	doc, err := s.client.Collection("mcp_front_execution_sessions").Doc(sessionID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var sessionDoc ExecutionSessionDoc
	if err := doc.DataTo(&sessionDoc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return sessionDoc.ToExecutionSession(), nil
}

// UpdateExecutionSession updates an existing execution session in Firestore
func (s *FirestoreStorage) UpdateExecutionSession(ctx context.Context, session *ExecutionSession) error {
	doc := FromExecutionSession(session)

	_, err := s.client.Collection("mcp_front_execution_sessions").Doc(session.SessionID).Set(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

// DeleteExecutionSession deletes an execution session from Firestore
func (s *FirestoreStorage) DeleteExecutionSession(ctx context.Context, sessionID string) error {
	_, err := s.client.Collection("mcp_front_execution_sessions").Doc(sessionID).Delete(ctx)
	if err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// RecordSessionActivity updates the last heartbeat and extends expiration
// Uses a Firestore transaction to prevent race conditions when multiple
// concurrent requests update the same session
func (s *FirestoreStorage) RecordSessionActivity(ctx context.Context, sessionID string) error {
	ref := s.client.Collection("mcp_front_execution_sessions").Doc(sessionID)

	// Use transaction to ensure atomic read-modify-write
	err := s.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		// Read current session within transaction
		doc, err := tx.Get(ref)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return ErrSessionNotFound
			}
			return fmt.Errorf("failed to get session: %w", err)
		}

		var sessionDoc ExecutionSessionDoc
		if err := doc.DataTo(&sessionDoc); err != nil {
			return fmt.Errorf("failed to unmarshal session: %w", err)
		}

		// Calculate new values
		now := time.Now()
		newExpiry := now.Add(time.Duration(sessionDoc.IdleTimeout) * time.Second)

		// Update within transaction (atomic with the read above)
		return tx.Update(ref, []firestore.Update{
			{Path: "last_heartbeat", Value: now.Unix()},
			{Path: "expires_at", Value: newExpiry.Unix()},
			{Path: "request_count", Value: firestore.Increment(1)},
		})
	})

	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return err
		}
		if status.Code(err) == codes.NotFound {
			return ErrSessionNotFound
		}
		return fmt.Errorf("failed to record activity: %w", err)
	}

	return nil
}

// ListUserExecutionSessions returns all active execution sessions for a user
func (s *FirestoreStorage) ListUserExecutionSessions(ctx context.Context, userEmail string) ([]*ExecutionSession, error) {
	// Query sessions for user that haven't expired yet
	now := time.Now().Unix()
	iter := s.client.Collection("mcp_front_execution_sessions").
		Where("user_email", "==", userEmail).
		Where("expires_at", ">", now).
		Documents(ctx)
	defer iter.Stop()

	var sessions []*ExecutionSession
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate sessions: %w", err)
		}

		var sessionDoc ExecutionSessionDoc
		if err := doc.DataTo(&sessionDoc); err != nil {
			log.LogError("Failed to unmarshal execution session: %v", err)
			continue
		}

		session := sessionDoc.ToExecutionSession()

		// Double-check expiration (includes all expiry conditions)
		if !session.IsExpired() {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// ListAllExecutionSessions returns all active execution sessions (admin only)
func (s *FirestoreStorage) ListAllExecutionSessions(ctx context.Context) ([]*ExecutionSession, error) {
	// Query sessions that haven't expired yet
	now := time.Now().Unix()
	iter := s.client.Collection("mcp_front_execution_sessions").
		Where("expires_at", ">", now).
		Documents(ctx)
	defer iter.Stop()

	var sessions []*ExecutionSession
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate sessions: %w", err)
		}

		var sessionDoc ExecutionSessionDoc
		if err := doc.DataTo(&sessionDoc); err != nil {
			log.LogError("Failed to unmarshal execution session: %v", err)
			continue
		}

		session := sessionDoc.ToExecutionSession()

		// Double-check expiration (includes all expiry conditions)
		if !session.IsExpired() {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

// CleanupExpiredSessions removes all expired execution sessions
func (s *FirestoreStorage) CleanupExpiredSessions(ctx context.Context) (int, error) {
	// Query sessions that have expired (by inactivity - simplest check)
	now := time.Now().Unix()
	iter := s.client.Collection("mcp_front_execution_sessions").
		Where("expires_at", "<=", now).
		Documents(ctx)
	defer iter.Stop()

	count := 0
	batch := s.client.Batch()
	batchSize := 0
	const maxBatchSize = 500 // Firestore batch write limit

	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return count, fmt.Errorf("failed to iterate expired sessions: %w", err)
		}

		// Delete in batch for efficiency
		batch.Delete(doc.Ref)
		batchSize++
		count++

		// Commit batch if we hit the limit
		if batchSize >= maxBatchSize {
			if _, err := batch.Commit(ctx); err != nil {
				return count, fmt.Errorf("failed to commit batch: %w", err)
			}
			batch = s.client.Batch()
			batchSize = 0
		}
	}

	// Commit remaining deletes
	if batchSize > 0 {
		if _, err := batch.Commit(ctx); err != nil {
			return count, fmt.Errorf("failed to commit final batch: %w", err)
		}
	}

	if count > 0 {
		log.LogInfoWithFields("firestore", "Cleaned up expired execution sessions", map[string]any{
			"count": count,
		})
	}

	return count, nil
}
