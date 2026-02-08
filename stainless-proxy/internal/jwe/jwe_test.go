package jwe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func TestRoundTrip(t *testing.T) {
	key := generateTestKey(t)
	kid := "test-key-1"

	enc := NewEncryptor(&key.PublicKey, kid)
	dec := NewMultiKeyDecryptor([]KeyEntry{{KID: kid, PrivateKey: key}})

	payload := Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: []string{"api.example.com"},
		Credentials: []Credential{
			{Header: "Authorization", Value: "Bearer secret-token"},
			{Header: "X-Api-Key", Value: "key-123"},
		},
	}

	token, err := enc.Encrypt(payload)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	got, err := dec.Decrypt(token)
	require.NoError(t, err)
	assert.Equal(t, payload.Exp, got.Exp)
	assert.Equal(t, payload.AllowedHosts, got.AllowedHosts)
	assert.Equal(t, payload.Credentials, got.Credentials)
}

func TestExpiredToken(t *testing.T) {
	key := generateTestKey(t)
	kid := "test-key-1"

	enc := NewEncryptor(&key.PublicKey, kid)
	dec := NewMultiKeyDecryptor([]KeyEntry{{KID: kid, PrivateKey: key}})

	payload := Payload{
		Exp:          time.Now().Add(-time.Hour).Unix(),
		AllowedHosts: []string{"api.example.com"},
		Credentials:  []Credential{{Header: "Authorization", Value: "Bearer x"}},
	}

	token, err := enc.Encrypt(payload)
	require.NoError(t, err)

	_, err = dec.Decrypt(token)
	assert.ErrorContains(t, err, "expired")
}

func TestWrongKey(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	enc := NewEncryptor(&key1.PublicKey, "key1")
	dec := NewMultiKeyDecryptor([]KeyEntry{{KID: "key2", PrivateKey: key2}})

	payload := Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: []string{"api.example.com"},
		Credentials:  []Credential{{Header: "Authorization", Value: "Bearer x"}},
	}

	token, err := enc.Encrypt(payload)
	require.NoError(t, err)

	_, err = dec.Decrypt(token)
	assert.Error(t, err)
}

func TestMultipleKeys(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	dec := NewMultiKeyDecryptor([]KeyEntry{
		{KID: "key1", PrivateKey: key1},
		{KID: "key2", PrivateKey: key2},
	})

	// Encrypt with key2
	enc := NewEncryptor(&key2.PublicKey, "key2")
	payload := Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: []string{"api.example.com"},
		Credentials:  []Credential{{Header: "X-Key", Value: "val"}},
	}

	token, err := enc.Encrypt(payload)
	require.NoError(t, err)

	got, err := dec.Decrypt(token)
	require.NoError(t, err)
	assert.Equal(t, "val", got.Credentials[0].Value)
}

func TestMissingAllowedHosts(t *testing.T) {
	key := generateTestKey(t)
	kid := "test-key-1"

	enc := NewEncryptor(&key.PublicKey, kid)
	dec := NewMultiKeyDecryptor([]KeyEntry{{KID: kid, PrivateKey: key}})

	payload := Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: nil,
		Credentials:  []Credential{{Header: "X-Key", Value: "val"}},
	}

	token, err := enc.Encrypt(payload)
	require.NoError(t, err)

	_, err = dec.Decrypt(token)
	assert.ErrorContains(t, err, "allowed_hosts")
}

func TestMissingCredentials(t *testing.T) {
	key := generateTestKey(t)
	kid := "test-key-1"

	enc := NewEncryptor(&key.PublicKey, kid)
	dec := NewMultiKeyDecryptor([]KeyEntry{{KID: kid, PrivateKey: key}})

	payload := Payload{
		Exp:          time.Now().Add(time.Hour).Unix(),
		AllowedHosts: []string{"api.example.com"},
		Credentials:  nil,
	}

	token, err := enc.Encrypt(payload)
	require.NoError(t, err)

	_, err = dec.Decrypt(token)
	assert.ErrorContains(t, err, "credentials")
}
