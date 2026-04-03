package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/idp"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/oauth"
)

var _ Storage = (*SQLiteStorage)(nil)

type SQLiteStorage struct {
	db           *sql.DB
	clients      map[string]*Client
	clientsMutex sync.RWMutex
	encryptor    crypto.Encryptor
}

func NewSQLiteStorage(ctx context.Context, dbPath string, encryptor crypto.Encryptor) (*SQLiteStorage, error) {
	if encryptor == nil {
		return nil, fmt.Errorf("encryptor is required")
	}
	if dbPath == "" {
		return nil, fmt.Errorf("database path is required")
	}

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	db.SetMaxOpenConns(1)

	s := &SQLiteStorage{
		db:        db,
		clients:   make(map[string]*Client),
		encryptor: encryptor,
	}

	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := s.loadClients(ctx); err != nil {
		log.LogError("Failed to load clients from SQLite: %v", err)
	}

	return s, nil
}

func (s *SQLiteStorage) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS clients (
			id            TEXT PRIMARY KEY,
			secret        TEXT,
			redirect_uris TEXT NOT NULL,
			scopes        TEXT NOT NULL,
			grant_types   TEXT NOT NULL,
			response_types TEXT NOT NULL,
			audience      TEXT NOT NULL,
			public        INTEGER NOT NULL,
			created_at    INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS grants (
			code           TEXT PRIMARY KEY,
			client_id      TEXT NOT NULL,
			redirect_uri   TEXT NOT NULL,
			identity       BLOB NOT NULL,
			scopes         TEXT NOT NULL,
			audience       TEXT NOT NULL,
			pkce_challenge TEXT NOT NULL,
			created_at     TEXT NOT NULL,
			expires_at     TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS user_tokens (
			user_email TEXT NOT NULL,
			service    TEXT NOT NULL,
			type       TEXT NOT NULL,
			value      TEXT,
			oauth_data TEXT,
			updated_at TEXT NOT NULL,
			PRIMARY KEY (user_email, service)
		);

		CREATE TABLE IF NOT EXISTS sessions (
			session_id  TEXT PRIMARY KEY,
			user_email  TEXT NOT NULL,
			server_name TEXT NOT NULL,
			created     TEXT NOT NULL,
			last_active TEXT NOT NULL
		);
	`)
	return err
}

func (s *SQLiteStorage) loadClients(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, secret, redirect_uris, scopes, grant_types, response_types, audience, public, created_at FROM clients`)
	if err != nil {
		return fmt.Errorf("failed to query clients: %w", err)
	}
	defer rows.Close()

	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	loadedCount := 0
	for rows.Next() {
		var (
			id            string
			secret        sql.NullString
			redirectURIs  string
			scopes        string
			grantTypes    string
			responseTypes string
			audience      string
			public        bool
			createdAt     int64
		)

		if err := rows.Scan(&id, &secret, &redirectURIs, &scopes, &grantTypes, &responseTypes, &audience, &public, &createdAt); err != nil {
			log.LogError("Failed to scan client row: %v", err)
			continue
		}

		var secretBytes []byte
		if secret.Valid && secret.String != "" {
			decrypted, err := s.encryptor.Decrypt(secret.String)
			if err != nil {
				log.LogError("Failed to decrypt client secret (client_id: %s): %v", id, err)
				continue
			}
			secretBytes = []byte(decrypted)
		}

		client := &Client{
			ID:            id,
			Secret:        secretBytes,
			RedirectURIs:  jsonStringSlice(redirectURIs),
			Scopes:        jsonStringSlice(scopes),
			GrantTypes:    jsonStringSlice(grantTypes),
			ResponseTypes: jsonStringSlice(responseTypes),
			Audience:      jsonStringSlice(audience),
			Public:        public,
			CreatedAt:     createdAt,
		}
		s.clients[id] = client
		loadedCount++
	}

	log.Logf("Loaded %d OAuth clients from SQLite", loadedCount)
	return rows.Err()
}

func (s *SQLiteStorage) GetClient(ctx context.Context, id string) (*Client, error) {
	s.clientsMutex.RLock()
	client, ok := s.clients[id]
	s.clientsMutex.RUnlock()

	if ok {
		return client.clone(), nil
	}

	return s.loadClient(ctx, id)
}

func (s *SQLiteStorage) loadClient(ctx context.Context, clientID string) (*Client, error) {
	var (
		id            string
		secret        sql.NullString
		redirectURIs  string
		scopes        string
		grantTypes    string
		responseTypes string
		audience      string
		public        bool
		createdAt     int64
	)

	err := s.db.QueryRowContext(ctx,
		`SELECT id, secret, redirect_uris, scopes, grant_types, response_types, audience, public, created_at FROM clients WHERE id = ?`,
		clientID,
	).Scan(&id, &secret, &redirectURIs, &scopes, &grantTypes, &responseTypes, &audience, &public, &createdAt)
	if err == sql.ErrNoRows {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get client from SQLite: %w", err)
	}

	var secretBytes []byte
	if secret.Valid && secret.String != "" {
		decrypted, err := s.encryptor.Decrypt(secret.String)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
		}
		secretBytes = []byte(decrypted)
	}

	client := &Client{
		ID:            id,
		Secret:        secretBytes,
		RedirectURIs:  jsonStringSlice(redirectURIs),
		Scopes:        jsonStringSlice(scopes),
		GrantTypes:    jsonStringSlice(grantTypes),
		ResponseTypes: jsonStringSlice(responseTypes),
		Audience:      jsonStringSlice(audience),
		Public:        public,
		CreatedAt:     createdAt,
	}

	s.clientsMutex.Lock()
	s.clients[clientID] = client
	s.clientsMutex.Unlock()

	return client.clone(), nil
}

func (s *SQLiteStorage) CreateClient(ctx context.Context, clientID string, redirectURIs []string, scopes []string, issuer string) (*Client, error) {
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

	if err := s.upsertClient(ctx, client); err != nil {
		return nil, err
	}

	s.clientsMutex.Lock()
	s.clients[clientID] = client
	clientCount := len(s.clients)
	s.clientsMutex.Unlock()

	log.Logf("Created client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client.clone(), nil
}

func (s *SQLiteStorage) CreateConfidentialClient(ctx context.Context, clientID string, hashedSecret []byte, redirectURIs []string, scopes []string, issuer string) (*Client, error) {
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

	if err := s.upsertClient(ctx, client); err != nil {
		return nil, err
	}

	s.clientsMutex.Lock()
	s.clients[clientID] = client
	clientCount := len(s.clients)
	s.clientsMutex.Unlock()

	log.Logf("Created confidential client %s, redirect_uris: %v, scopes: %v", clientID, redirectURIs, scopes)
	log.Logf("Total clients in storage: %d", clientCount)
	return client.clone(), nil
}

func (s *SQLiteStorage) upsertClient(ctx context.Context, client *Client) error {
	var encryptedSecret sql.NullString
	if len(client.Secret) > 0 {
		encrypted, err := s.encryptor.Encrypt(string(client.Secret))
		if err != nil {
			return fmt.Errorf("failed to encrypt client secret: %w", err)
		}
		encryptedSecret = sql.NullString{String: encrypted, Valid: true}
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO clients (id, secret, redirect_uris, scopes, grant_types, response_types, audience, public, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		client.ID,
		encryptedSecret,
		toJSONString(client.RedirectURIs),
		toJSONString(client.Scopes),
		toJSONString(client.GrantTypes),
		toJSONString(client.ResponseTypes),
		toJSONString(client.Audience),
		client.Public,
		client.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store client in SQLite: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) StoreGrant(ctx context.Context, code string, grant *oauth.Grant) error {
	identityJSON, err := json.Marshal(grant.Identity)
	if err != nil {
		return fmt.Errorf("failed to encode identity: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO grants (code, client_id, redirect_uri, identity, scopes, audience, pkce_challenge, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code,
		grant.ClientID,
		grant.RedirectURI,
		identityJSON,
		toJSONString(grant.Scopes),
		toJSONString(grant.Audience),
		grant.PKCEChallenge,
		grant.CreatedAt.Format(time.RFC3339Nano),
		grant.ExpiresAt.Format(time.RFC3339Nano),
	)
	return err
}

func (s *SQLiteStorage) ConsumeGrant(ctx context.Context, code string) (*oauth.Grant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		clientID      string
		redirectURI   string
		identityJSON  []byte
		scopesJSON    string
		audienceJSON  string
		pkceChallenge string
		createdAtStr  string
		expiresAtStr  string
	)

	err = tx.QueryRowContext(ctx,
		`SELECT client_id, redirect_uri, identity, scopes, audience, pkce_challenge, created_at, expires_at FROM grants WHERE code = ?`,
		code,
	).Scan(&clientID, &redirectURI, &identityJSON, &scopesJSON, &audienceJSON, &pkceChallenge, &createdAtStr, &expiresAtStr)
	if err == sql.ErrNoRows {
		return nil, ErrGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get grant from SQLite: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM grants WHERE code = ?`, code); err != nil {
		return nil, fmt.Errorf("failed to delete grant: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	var identity idp.Identity
	if err := json.Unmarshal(identityJSON, &identity); err != nil {
		return nil, fmt.Errorf("failed to decode identity: %w", err)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grant created_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grant expires_at: %w", err)
	}

	return &oauth.Grant{
		Code:          code,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Identity:      identity,
		Scopes:        jsonStringSlice(scopesJSON),
		Audience:      jsonStringSlice(audienceJSON),
		PKCEChallenge: pkceChallenge,
		CreatedAt:     createdAt,
		ExpiresAt:     expiresAt,
	}, nil
}

func (s *SQLiteStorage) GetUserToken(ctx context.Context, userEmail, service string) (*StoredToken, error) {
	var (
		tokenType    string
		value        sql.NullString
		oauthDataStr sql.NullString
		updatedAtStr string
	)

	err := s.db.QueryRowContext(ctx,
		`SELECT type, value, oauth_data, updated_at FROM user_tokens WHERE user_email = ? AND service = ?`,
		userEmail, service,
	).Scan(&tokenType, &value, &oauthDataStr, &updatedAtStr)
	if err == sql.ErrNoRows {
		return nil, ErrUserTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user token from SQLite: %w", err)
	}

	updatedAt, err := time.Parse(time.RFC3339Nano, updatedAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token updated_at: %w", err)
	}
	storedToken := &StoredToken{
		Type:      TokenType(tokenType),
		UpdatedAt: updatedAt,
	}

	switch storedToken.Type {
	case TokenTypeManual:
		if value.Valid && value.String != "" {
			decrypted, err := s.encryptor.Decrypt(value.String)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt manual token: %w", err)
			}
			storedToken.Value = decrypted
		}
	case TokenTypeOAuth:
		if oauthDataStr.Valid && oauthDataStr.String != "" {
			var oauthData OAuthTokenData
			if err := json.Unmarshal([]byte(oauthDataStr.String), &oauthData); err != nil {
				return nil, fmt.Errorf("failed to unmarshal oauth data: %w", err)
			}

			decryptedAccess, err := s.encryptor.Decrypt(oauthData.AccessToken)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt access token: %w", err)
			}
			oauthData.AccessToken = decryptedAccess

			if oauthData.RefreshToken != "" {
				decryptedRefresh, err := s.encryptor.Decrypt(oauthData.RefreshToken)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
				}
				oauthData.RefreshToken = decryptedRefresh
			}

			storedToken.OAuthData = &oauthData
		}
	}

	return storedToken, nil
}

func (s *SQLiteStorage) SetUserToken(ctx context.Context, userEmail, service string, token *StoredToken) error {
	if token == nil {
		return fmt.Errorf("token cannot be nil")
	}

	var encryptedValue sql.NullString
	var oauthDataStr sql.NullString

	switch token.Type {
	case TokenTypeManual:
		if token.Value != "" {
			encrypted, err := s.encryptor.Encrypt(token.Value)
			if err != nil {
				return fmt.Errorf("failed to encrypt manual token: %w", err)
			}
			encryptedValue = sql.NullString{String: encrypted, Valid: true}
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

			data, err := json.Marshal(oauthData)
			if err != nil {
				return fmt.Errorf("failed to marshal oauth data: %w", err)
			}
			oauthDataStr = sql.NullString{String: string(data), Valid: true}
		}
	default:
		return fmt.Errorf("unknown token type: %s", token.Type)
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO user_tokens (user_email, service, type, value, oauth_data, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		userEmail, service, string(token.Type), encryptedValue, oauthDataStr, time.Now().Format(time.RFC3339Nano),
	)
	return err
}

func (s *SQLiteStorage) DeleteUserToken(ctx context.Context, userEmail, service string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_tokens WHERE user_email = ? AND service = ?`,
		userEmail, service,
	)
	return err
}

func (s *SQLiteStorage) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT service FROM user_tokens WHERE user_email = ?`,
		userEmail,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list user services: %w", err)
	}
	defer rows.Close()

	var services []string
	for rows.Next() {
		var service string
		if err := rows.Scan(&service); err != nil {
			return nil, fmt.Errorf("failed to scan service: %w", err)
		}
		services = append(services, service)
	}
	return services, rows.Err()
}

func (s *SQLiteStorage) TrackSession(ctx context.Context, session ActiveSession) error {
	now := time.Now()
	if session.Created.IsZero() {
		session.Created = now
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (session_id, user_email, server_name, created, last_active)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(session_id) DO UPDATE SET last_active = ?`,
		session.SessionID, session.UserEmail, session.ServerName,
		session.Created.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
	)
	return err
}

func (s *SQLiteStorage) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE session_id = ?`, sessionID)
	return err
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

func toJSONString(s []string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

func jsonStringSlice(s string) []string {
	var result []string
	json.Unmarshal([]byte(s), &result)
	return result
}
