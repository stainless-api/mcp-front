package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"encoding/json"

	"cloud.google.com/go/firestore"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	sessionsCollection = "mcp_front_sessions"
	grantsCollection   = "mcp_front_grants"
)

type FirestoreStorage struct {
	client          *firestore.Client
	clients         map[string]*Client
	clientsMutex    sync.RWMutex
	projectID       string
	collection      string
	encryptor       crypto.Encryptor
	tokenCollection string
}

var _ Storage = (*FirestoreStorage)(nil)

type UserTokenDoc struct {
	UserEmail string          `firestore:"user_email"`
	Service   string          `firestore:"service"`
	Type      TokenType       `firestore:"type"`
	Value     string          `firestore:"value,omitempty"`
	OAuthData *OAuthTokenData `firestore:"oauth_data,omitempty"`
	UpdatedAt time.Time       `firestore:"updated_at"`
}

type OAuthClientEntity struct {
	ID            string   `firestore:"id"`
	Secret        *string  `firestore:"secret,omitempty"`
	RedirectURIs  []string `firestore:"redirect_uris"`
	Scopes        []string `firestore:"scopes"`
	GrantTypes    []string `firestore:"grant_types"`
	ResponseTypes []string `firestore:"response_types"`
	Audience      []string `firestore:"audience"`
	Public        bool     `firestore:"public"`
	CreatedAt     int64    `firestore:"created_at"`
}

func (e *OAuthClientEntity) ToClient(encryptor crypto.Encryptor) (*Client, error) {
	var secret []byte
	if e.Secret != nil {
		decrypted, err := encryptor.Decrypt(*e.Secret)
		if err != nil {
			return nil, fmt.Errorf("decrypting client secret: %w", err)
		}
		secret = []byte(decrypted)
	}

	return &Client{
		ID:            e.ID,
		Secret:        secret,
		RedirectURIs:  e.RedirectURIs,
		Scopes:        e.Scopes,
		GrantTypes:    e.GrantTypes,
		ResponseTypes: e.ResponseTypes,
		Audience:      e.Audience,
		Public:        e.Public,
		CreatedAt:     e.CreatedAt,
	}, nil
}

func ClientToEntity(client *Client, encryptor crypto.Encryptor) (*OAuthClientEntity, error) {
	var secret *string
	if len(client.Secret) > 0 {
		encrypted, err := encryptor.Encrypt(string(client.Secret))
		if err != nil {
			return nil, fmt.Errorf("encrypting client secret: %w", err)
		}
		secret = &encrypted
	}

	return &OAuthClientEntity{
		ID:            client.ID,
		Secret:        secret,
		RedirectURIs:  client.RedirectURIs,
		Scopes:        client.Scopes,
		GrantTypes:    client.GrantTypes,
		ResponseTypes: client.ResponseTypes,
		Audience:      client.Audience,
		Public:        client.Public,
		CreatedAt:     client.CreatedAt,
	}, nil
}

type GrantEntity struct {
	Code          string    `firestore:"code"`
	ClientID      string    `firestore:"client_id"`
	RedirectURI   string    `firestore:"redirect_uri"`
	Identity      []byte    `firestore:"identity"`
	Scopes        []string  `firestore:"scopes"`
	Audience      []string  `firestore:"audience"`
	PKCEChallenge string    `firestore:"pkce_challenge"`
	CreatedAt     time.Time `firestore:"created_at"`
	ExpiresAt     time.Time `firestore:"expires_at"`
}

func NewFirestoreStorage(ctx context.Context, projectID, database, collection string, encryptor crypto.Encryptor) (*FirestoreStorage, error) {
	if encryptor == nil {
		return nil, fmt.Errorf("encryptor is required")
	}

	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if collection == "" {
		return nil, fmt.Errorf("collection is required")
	}

	var client *firestore.Client
	var err error

	if database != "" && database != "(default)" {
		client, err = firestore.NewClientWithDatabase(ctx, projectID, database)
	} else {
		client, err = firestore.NewClient(ctx, projectID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create Firestore client: %w", err)
	}

	storage := &FirestoreStorage{
		client:          client,
		clients:         make(map[string]*Client),
		projectID:       projectID,
		collection:      collection,
		encryptor:       encryptor,
		tokenCollection: "mcp_front_user_tokens",
	}

	if err := storage.loadClientsFromFirestore(ctx); err != nil {
		log.LogError("Failed to load clients from Firestore: %v", err)
	}

	return storage, nil
}

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

		client, err := entity.ToClient(s.encryptor)
		if err != nil {
			log.LogError("Failed to decrypt client secret (client_id: %s): %v", entity.ID, err)
			continue
		}
		s.clients[entity.ID] = client
		loadedCount++
	}

	log.Logf("Loaded %d OAuth clients from Firestore", loadedCount)
	return nil
}

func (s *FirestoreStorage) GetClient(ctx context.Context, id string) (*Client, error) {
	s.clientsMutex.RLock()
	client, ok := s.clients[id]
	s.clientsMutex.RUnlock()

	if ok {
		return client, nil
	}

	return s.loadClientFromFirestore(ctx, id)
}

func (s *FirestoreStorage) loadClientFromFirestore(ctx context.Context, clientID string) (*Client, error) {
	doc, err := s.client.Collection(s.collection).Doc(clientID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("failed to get client from Firestore: %w", err)
	}

	var entity OAuthClientEntity
	if err := doc.DataTo(&entity); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client: %w", err)
	}

	client, err := entity.ToClient(s.encryptor)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	s.clientsMutex.Lock()
	s.clients[clientID] = client
	s.clientsMutex.Unlock()

	return client, nil
}

func (s *FirestoreStorage) CreateClient(ctx context.Context, clientID string, redirectURIs []string, scopes []string, issuer string) (*Client, error) {
	client := &Client{
		ID:            clientID,
		Secret:        nil,
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        true,
		CreatedAt:     time.Now().Unix(),
	}

	entity, err := ClientToEntity(client, s.encryptor)
	if err != nil {
		log.LogError("Failed to encrypt client for Firestore (client_id: %s): %v", clientID, err)
		return nil, fmt.Errorf("failed to encrypt client: %w", err)
	}

	if _, err := s.client.Collection(s.collection).Doc(clientID).Set(ctx, entity); err != nil {
		log.LogError("Failed to store client in Firestore (client_id: %s): %v", clientID, err)
		return nil, fmt.Errorf("failed to store client in Firestore: %w", err)
	}

	log.Logf("Stored client %s in Firestore", clientID)

	s.clientsMutex.Lock()
	s.clients[clientID] = client
	clientCount := len(s.clients)
	s.clientsMutex.Unlock()

	log.Logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client, nil
}

func (s *FirestoreStorage) CreateConfidentialClient(ctx context.Context, clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) (*Client, error) {
	client := &Client{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  redirectURIs,
		Scopes:        scopes,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Audience:      []string{issuer},
		Public:        false,
		CreatedAt:     time.Now().Unix(),
	}

	entity, err := ClientToEntity(client, s.encryptor)
	if err != nil {
		log.LogError("Failed to encrypt client for Firestore (client_id: %s): %v", clientID, err)
		return nil, fmt.Errorf("failed to encrypt client: %w", err)
	}

	if _, err := s.client.Collection(s.collection).Doc(clientID).Set(ctx, entity); err != nil {
		log.LogError("Failed to store client in Firestore (client_id: %s): %v", clientID, err)
		return nil, fmt.Errorf("failed to store client in Firestore: %w", err)
	}

	log.Logf("Stored confidential client %s in Firestore", clientID)

	s.clientsMutex.Lock()
	s.clients[clientID] = client
	clientCount := len(s.clients)
	s.clientsMutex.Unlock()

	log.Logf("Created confidential client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client, nil
}

func (s *FirestoreStorage) StoreGrant(ctx context.Context, code string, grant *oauth.Grant) error {
	identityJSON, err := encodeJSON(grant.Identity)
	if err != nil {
		return fmt.Errorf("failed to encode identity: %w", err)
	}

	entity := GrantEntity{
		Code:          code,
		ClientID:      grant.ClientID,
		RedirectURI:   grant.RedirectURI,
		Identity:      identityJSON,
		Scopes:        grant.Scopes,
		Audience:      grant.Audience,
		PKCEChallenge: grant.PKCEChallenge,
		CreatedAt:     grant.CreatedAt,
		ExpiresAt:     grant.ExpiresAt,
	}

	if _, err := s.client.Collection(grantsCollection).Doc(code).Set(ctx, entity); err != nil {
		return fmt.Errorf("failed to store grant in Firestore: %w", err)
	}
	return nil
}

func (s *FirestoreStorage) ConsumeGrant(ctx context.Context, code string) (*oauth.Grant, error) {
	docRef := s.client.Collection(grantsCollection).Doc(code)

	var entity GrantEntity
	err := s.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		doc, err := tx.Get(docRef)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return ErrGrantNotFound
			}
			return fmt.Errorf("failed to get grant from Firestore: %w", err)
		}

		if err := doc.DataTo(&entity); err != nil {
			return fmt.Errorf("failed to unmarshal grant: %w", err)
		}

		return tx.Delete(docRef)
	})
	if err != nil {
		return nil, err
	}

	var identity idp.Identity
	if err := decodeJSON(entity.Identity, &identity); err != nil {
		return nil, fmt.Errorf("failed to decode identity: %w", err)
	}

	return &oauth.Grant{
		Code:          entity.Code,
		ClientID:      entity.ClientID,
		RedirectURI:   entity.RedirectURI,
		Identity:      identity,
		Scopes:        entity.Scopes,
		Audience:      entity.Audience,
		PKCEChallenge: entity.PKCEChallenge,
		CreatedAt:     entity.CreatedAt,
		ExpiresAt:     entity.ExpiresAt,
	}, nil
}

func (s *FirestoreStorage) Close() error {
	return s.client.Close()
}

// User token methods

func (s *FirestoreStorage) makeUserTokenDocID(userEmail, service string) string {
	return userEmail + "__" + service
}

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

	storedToken := &StoredToken{
		Type:      tokenDoc.Type,
		UpdatedAt: tokenDoc.UpdatedAt,
	}

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

func (s *FirestoreStorage) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	docID := s.makeUserTokenDocID(userEmail, service)
	_, err := s.client.Collection(s.tokenCollection).Doc(docID).Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete token from Firestore: %w", err)
	}
	return nil
}

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
			log.LogError("Failed to unmarshal user token: %v", err)
			continue
		}

		services = append(services, tokenDoc.Service)
	}

	return services, nil
}

type SessionDoc struct {
	SessionID  string    `firestore:"session_id"`
	UserEmail  string    `firestore:"user_email"`
	ServerName string    `firestore:"server_name"`
	Created    time.Time `firestore:"created"`
	LastActive time.Time `firestore:"last_active"`
}

func (s *FirestoreStorage) TrackSession(ctx context.Context, session ActiveSession) error {
	now := time.Now()
	if session.Created.IsZero() {
		session.Created = now
	}

	sessionDoc := SessionDoc{
		SessionID:  session.SessionID,
		UserEmail:  session.UserEmail,
		ServerName: session.ServerName,
		Created:    session.Created,
		LastActive: now,
	}

	_, err := s.client.Collection(sessionsCollection).Doc(session.SessionID).Set(ctx, sessionDoc)
	return err
}

func (s *FirestoreStorage) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := s.client.Collection(sessionsCollection).Doc(sessionID).Delete(ctx)
	if err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	return nil
}

func encodeJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func decodeJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
