package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/idp"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newTestSQLiteStorage(t *testing.T) *SQLiteStorage {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	key := []byte("01234567890123456789012345678901")
	encryptor, err := crypto.NewEncryptor(key)
	require.NoError(t, err)
	s, err := NewSQLiteStorage(context.Background(), dbPath, encryptor)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLiteStorageDefault(t *testing.T) {
	s := newTestSQLiteStorage(t)
	assert.NotNil(t, s)
}

func TestSQLiteStorageRequiresEncryptor(t *testing.T) {
	dir := t.TempDir()
	_, err := NewSQLiteStorage(context.Background(), filepath.Join(dir, "test.db"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encryptor is required")
}

func TestSQLiteStorageRequiresPath(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	enc, _ := crypto.NewEncryptor(key)
	_, err := NewSQLiteStorage(context.Background(), "", enc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database path is required")
}

func TestSQLiteStorageConfidentialClient(t *testing.T) {
	store := newTestSQLiteStorage(t)
	ctx := context.Background()

	clientID := "test-client-123"
	secret, err := crypto.GenerateSecureToken()
	require.NoError(t, err)
	hashedSecret, err := crypto.HashClientSecret(secret)
	require.NoError(t, err)

	redirectURIs := []string{"https://example.com/callback"}
	scopes := []string{"read", "write"}
	issuer := "https://issuer.example.com"

	client, err := store.CreateConfidentialClient(ctx, clientID, hashedSecret, redirectURIs, scopes, issuer)
	require.NoError(t, err)

	assert.Equal(t, clientID, client.ID)
	assert.Equal(t, hashedSecret, client.Secret)
	assert.Equal(t, redirectURIs, client.RedirectURIs)
	assert.ElementsMatch(t, scopes, client.Scopes)
	assert.ElementsMatch(t, []string{issuer}, client.Audience)
	assert.False(t, client.Public)

	storedClient, err := store.GetClient(ctx, clientID)
	require.NoError(t, err)
	assert.Equal(t, clientID, storedClient.GetID())
	assert.False(t, storedClient.IsPublic())

	err = bcrypt.CompareHashAndPassword(storedClient.GetSecret(), []byte(secret))
	assert.NoError(t, err)
}

func TestSQLiteStoragePublicVsConfidential(t *testing.T) {
	store := newTestSQLiteStorage(t)
	ctx := context.Background()

	publicClient, err := store.CreateClient(ctx, "public-123", []string{"https://public.com/callback"}, []string{"read"}, "https://issuer.com")
	require.NoError(t, err)
	assert.True(t, publicClient.Public)
	assert.Nil(t, publicClient.Secret)

	hashedSecret := []byte("hashed-secret")
	confidentialClient, err := store.CreateConfidentialClient(ctx, "confidential-123", hashedSecret, []string{"https://confidential.com/callback"}, []string{"read"}, "https://issuer.com")
	require.NoError(t, err)
	assert.False(t, confidentialClient.Public)
	assert.NotNil(t, confidentialClient.Secret)
	assert.Equal(t, hashedSecret, confidentialClient.Secret)
}

func TestSQLiteStorageGrants(t *testing.T) {
	store := newTestSQLiteStorage(t)
	ctx := context.Background()

	grant := &oauth.Grant{
		Code:        "test-code",
		ClientID:    "client-123",
		RedirectURI: "https://example.com/callback",
		Identity: idp.Identity{
			Email:  "user@example.com",
			Domain: "example.com",
		},
		Scopes:        []string{"read", "write"},
		Audience:      []string{"https://issuer.com"},
		PKCEChallenge: "challenge-value",
		CreatedAt:     time.Now().Truncate(time.Millisecond),
		ExpiresAt:     time.Now().Add(10 * time.Minute).Truncate(time.Millisecond),
	}

	t.Run("store and consume", func(t *testing.T) {
		err := store.StoreGrant(ctx, grant.Code, grant)
		require.NoError(t, err)

		consumed, err := store.ConsumeGrant(ctx, grant.Code)
		require.NoError(t, err)
		assert.Equal(t, grant.ClientID, consumed.ClientID)
		assert.Equal(t, grant.Identity.Email, consumed.Identity.Email)
		assert.Equal(t, grant.Scopes, consumed.Scopes)
		assert.Equal(t, grant.PKCEChallenge, consumed.PKCEChallenge)
	})

	t.Run("consume is one-time", func(t *testing.T) {
		err := store.StoreGrant(ctx, "one-time-code", grant)
		require.NoError(t, err)

		_, err = store.ConsumeGrant(ctx, "one-time-code")
		require.NoError(t, err)

		_, err = store.ConsumeGrant(ctx, "one-time-code")
		require.ErrorIs(t, err, ErrGrantNotFound)
	})

	t.Run("consume nonexistent grant", func(t *testing.T) {
		_, err := store.ConsumeGrant(ctx, "nonexistent")
		require.ErrorIs(t, err, ErrGrantNotFound)
	})
}

func TestSQLiteStorageClientNotFound(t *testing.T) {
	store := newTestSQLiteStorage(t)
	_, err := store.GetClient(context.Background(), "nonexistent")
	require.ErrorIs(t, err, ErrClientNotFound)
}

func TestSQLiteStorageUserTokens(t *testing.T) {
	store := newTestSQLiteStorage(t)
	ctx := context.Background()

	t.Run("manual token", func(t *testing.T) {
		token := &StoredToken{
			Type:  TokenTypeManual,
			Value: "secret-api-key",
		}
		err := store.SetUserToken(ctx, "user@example.com", "linear", token)
		require.NoError(t, err)

		stored, err := store.GetUserToken(ctx, "user@example.com", "linear")
		require.NoError(t, err)
		assert.Equal(t, TokenTypeManual, stored.Type)
		assert.Equal(t, "secret-api-key", stored.Value)
	})

	t.Run("oauth token", func(t *testing.T) {
		token := &StoredToken{
			Type: TokenTypeOAuth,
			OAuthData: &OAuthTokenData{
				AccessToken:  "access-123",
				RefreshToken: "refresh-456",
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				Scopes:       []string{"read"},
			},
		}
		err := store.SetUserToken(ctx, "user@example.com", "notion", token)
		require.NoError(t, err)

		stored, err := store.GetUserToken(ctx, "user@example.com", "notion")
		require.NoError(t, err)
		assert.Equal(t, TokenTypeOAuth, stored.Type)
		assert.Equal(t, "access-123", stored.OAuthData.AccessToken)
		assert.Equal(t, "refresh-456", stored.OAuthData.RefreshToken)
	})

	t.Run("list services", func(t *testing.T) {
		services, err := store.ListUserServices(ctx, "user@example.com")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"linear", "notion"}, services)
	})

	t.Run("delete token", func(t *testing.T) {
		err := store.DeleteUserToken(ctx, "user@example.com", "linear")
		require.NoError(t, err)

		_, err = store.GetUserToken(ctx, "user@example.com", "linear")
		require.ErrorIs(t, err, ErrUserTokenNotFound)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := store.GetUserToken(ctx, "nobody@example.com", "service")
		require.ErrorIs(t, err, ErrUserTokenNotFound)
	})
}

func TestSQLiteStorageSessions(t *testing.T) {
	store := newTestSQLiteStorage(t)
	ctx := context.Background()

	t.Run("track new session", func(t *testing.T) {
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-1",
			UserEmail:  "user@example.com",
			ServerName: "postgres",
			Created:    time.Now().Add(-1 * time.Minute),
		})
		require.NoError(t, err)
	})

	t.Run("track session updates last_active", func(t *testing.T) {
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-1",
			UserEmail:  "user@example.com",
			ServerName: "postgres",
		})
		require.NoError(t, err)
	})

	t.Run("revoke session", func(t *testing.T) {
		err := store.RevokeSession(ctx, "sess-1")
		require.NoError(t, err)
	})

	t.Run("revoke nonexistent session is idempotent", func(t *testing.T) {
		err := store.RevokeSession(ctx, "nonexistent")
		require.NoError(t, err)
	})
}

func TestSQLiteStoragePersistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist.db")
	key := []byte("01234567890123456789012345678901")
	encryptor, err := crypto.NewEncryptor(key)
	require.NoError(t, err)
	ctx := context.Background()

	s1, err := NewSQLiteStorage(ctx, dbPath, encryptor)
	require.NoError(t, err)

	_, err = s1.CreateClient(ctx, "persist-client", []string{"https://example.com/cb"}, []string{"read"}, "https://issuer.com")
	require.NoError(t, err)

	err = s1.SetUserToken(ctx, "user@example.com", "linear", &StoredToken{
		Type:  TokenTypeManual,
		Value: "my-token",
	})
	require.NoError(t, err)
	s1.Close()

	s2, err := NewSQLiteStorage(ctx, dbPath, encryptor)
	require.NoError(t, err)
	defer s2.Close()

	client, err := s2.GetClient(ctx, "persist-client")
	require.NoError(t, err)
	assert.Equal(t, "persist-client", client.ID)

	token, err := s2.GetUserToken(ctx, "user@example.com", "linear")
	require.NoError(t, err)
	assert.Equal(t, "my-token", token.Value)
}

func TestSQLiteStorageFileCreated(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "subdir", "test.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)
	key := []byte("01234567890123456789012345678901")
	enc, _ := crypto.NewEncryptor(key)
	s, err := NewSQLiteStorage(context.Background(), dbPath, enc)
	require.NoError(t, err)
	s.Close()

	_, err = os.Stat(dbPath)
	assert.NoError(t, err)
}

func TestSQLiteStorageClientIsolation(t *testing.T) {
	store := newTestSQLiteStorage(t)
	ctx := context.Background()

	uris := []string{"https://example.com/callback"}
	scopes := []string{"read", "write"}

	_, err := store.CreateClient(ctx, "client-1", uris, scopes, "https://issuer.com")
	require.NoError(t, err)

	uris[0] = "https://attacker.com/callback"
	scopes[0] = "admin"

	stored, err := store.GetClient(ctx, "client-1")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/callback", stored.RedirectURIs[0], "stored client should not be affected by caller mutation")
	assert.Equal(t, "read", stored.Scopes[0], "stored client should not be affected by caller mutation")
}

func TestSQLiteStorageGetClientIsolation(t *testing.T) {
	store := newTestSQLiteStorage(t)
	ctx := context.Background()

	_, err := store.CreateClient(ctx, "client-2", []string{"https://example.com/callback"}, []string{"read"}, "https://issuer.com")
	require.NoError(t, err)

	c1, _ := store.GetClient(ctx, "client-2")
	c2, _ := store.GetClient(ctx, "client-2")

	c1.RedirectURIs[0] = "https://attacker.com"

	assert.Equal(t, "https://example.com/callback", c2.RedirectURIs[0], "mutating one copy should not affect another")
}
