package storage

import (
	"context"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestMemoryStorageConfidentialClient(t *testing.T) {
	store := NewMemoryStorage()

	clientID := "test-client-123"
	secret, err := crypto.GenerateClientSecret()
	assert.NoError(t, err)
	hashedSecret, err := crypto.HashClientSecret(secret)
	assert.NoError(t, err)

	redirectURIs := []string{"https://example.com/callback"}
	scopes := []string{"read", "write"}
	issuer := "https://issuer.example.com"

	client, err := store.CreateConfidentialClient(context.Background(), clientID, hashedSecret, redirectURIs, scopes, issuer)
	assert.NoError(t, err)

	assert.Equal(t, clientID, client.ID)
	assert.Equal(t, hashedSecret, client.Secret)
	assert.Equal(t, redirectURIs, client.RedirectURIs)
	assert.ElementsMatch(t, scopes, client.Scopes)
	assert.ElementsMatch(t, []string{issuer}, client.Audience)
	assert.False(t, client.Public)

	ctx := context.Background()
	storedClient, err := store.GetClient(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, storedClient)
	assert.Equal(t, clientID, storedClient.GetID())
	assert.False(t, storedClient.IsPublic())

	err = bcrypt.CompareHashAndPassword(storedClient.GetSecret(), []byte(secret))
	assert.NoError(t, err, "Original secret should verify against stored hash")
}

func TestMemoryStoragePublicVsConfidential(t *testing.T) {
	store := NewMemoryStorage()

	publicClient, err := store.CreateClient(context.Background(), "public-123", []string{"https://public.com/callback"}, []string{"read"}, "https://issuer.com")
	assert.NoError(t, err)
	assert.True(t, publicClient.Public)
	assert.Nil(t, publicClient.Secret)

	hashedSecret := []byte("hashed-secret")
	confidentialClient, err := store.CreateConfidentialClient(context.Background(), "confidential-123", hashedSecret, []string{"https://confidential.com/callback"}, []string{"read"}, "https://issuer.com")
	assert.NoError(t, err)
	assert.False(t, confidentialClient.Public)
	assert.NotNil(t, confidentialClient.Secret)
	assert.Equal(t, hashedSecret, confidentialClient.Secret)
}

func TestMemoryStorageGrants(t *testing.T) {
	store := NewMemoryStorage()
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
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
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

func TestMemoryStorageClientIsolation(t *testing.T) {
	store := NewMemoryStorage()
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

func TestMemoryStorageGetClientIsolation(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	_, err := store.CreateClient(ctx, "client-2", []string{"https://example.com/callback"}, []string{"read"}, "https://issuer.com")
	require.NoError(t, err)

	c1, _ := store.GetClient(ctx, "client-2")
	c2, _ := store.GetClient(ctx, "client-2")

	c1.RedirectURIs[0] = "https://attacker.com"

	assert.Equal(t, "https://example.com/callback", c2.RedirectURIs[0], "mutating one copy should not affect another")
}

func TestMemoryStorageSessions(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	t.Run("track new session", func(t *testing.T) {
		created := time.Now().Add(-1 * time.Minute)
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-1",
			UserEmail:  "user@example.com",
			ServerName: "postgres",
			Created:    created,
		})
		require.NoError(t, err)

		sessions, err := store.GetActiveSessions(ctx)
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		assert.Equal(t, "sess-1", sessions[0].SessionID)
		assert.Equal(t, "user@example.com", sessions[0].UserEmail)
		assert.Equal(t, "postgres", sessions[0].ServerName)
		assert.WithinDuration(t, created, sessions[0].Created, time.Second)
		assert.WithinDuration(t, time.Now(), sessions[0].LastActive, time.Second)
	})

	t.Run("track session sets Created when zero", func(t *testing.T) {
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-zero",
			UserEmail:  "user@example.com",
			ServerName: "linear",
		})
		require.NoError(t, err)

		sessions, err := store.GetActiveSessions(ctx)
		require.NoError(t, err)

		var found *ActiveSession
		for _, s := range sessions {
			if s.SessionID == "sess-zero" {
				found = &s
				break
			}
		}
		require.NotNil(t, found)
		assert.WithinDuration(t, time.Now(), found.Created, time.Second)
	})

	t.Run("track existing session updates LastActive", func(t *testing.T) {
		sessions, _ := store.GetActiveSessions(ctx)
		var before ActiveSession
		for _, s := range sessions {
			if s.SessionID == "sess-1" {
				before = s
				break
			}
		}

		time.Sleep(10 * time.Millisecond)
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-1",
			UserEmail:  "user@example.com",
			ServerName: "postgres",
		})
		require.NoError(t, err)

		sessions, _ = store.GetActiveSessions(ctx)
		var after ActiveSession
		for _, s := range sessions {
			if s.SessionID == "sess-1" {
				after = s
				break
			}
		}
		assert.True(t, after.LastActive.After(before.LastActive))
	})

	t.Run("revoke session", func(t *testing.T) {
		err := store.RevokeSession(ctx, "sess-1")
		require.NoError(t, err)

		sessions, err := store.GetActiveSessions(ctx)
		require.NoError(t, err)
		for _, s := range sessions {
			assert.NotEqual(t, "sess-1", s.SessionID)
		}
	})

	t.Run("revoke nonexistent session is idempotent", func(t *testing.T) {
		err := store.RevokeSession(ctx, "nonexistent")
		require.NoError(t, err)
	})

	t.Run("delete user cascades to sessions", func(t *testing.T) {
		err := store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-del-1",
			UserEmail:  "delete-me@example.com",
			ServerName: "postgres",
		})
		require.NoError(t, err)

		err = store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-del-2",
			UserEmail:  "delete-me@example.com",
			ServerName: "linear",
		})
		require.NoError(t, err)

		err = store.TrackSession(ctx, ActiveSession{
			SessionID:  "sess-keep",
			UserEmail:  "keep-me@example.com",
			ServerName: "postgres",
		})
		require.NoError(t, err)

		err = store.UpsertUser(ctx, "delete-me@example.com")
		require.NoError(t, err)

		err = store.DeleteUser(ctx, "delete-me@example.com")
		require.NoError(t, err)

		sessions, err := store.GetActiveSessions(ctx)
		require.NoError(t, err)
		for _, s := range sessions {
			assert.NotEqual(t, "delete-me@example.com", s.UserEmail)
		}

		var keepFound bool
		for _, s := range sessions {
			if s.SessionID == "sess-keep" {
				keepFound = true
			}
		}
		assert.True(t, keepFound, "other user's sessions should not be affected")
	})
}
