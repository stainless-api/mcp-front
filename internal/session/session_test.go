package session

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrowserCookie_MarshalUnmarshal(t *testing.T) {
	original := BrowserCookie{
		Email:    "user@example.com",
		Provider: "google",
		Expires:  time.Now().Add(24 * time.Hour).Truncate(time.Second),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var unmarshaled BrowserCookie
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.Email, unmarshaled.Email)
	assert.Equal(t, original.Provider, unmarshaled.Provider)
	assert.WithinDuration(t, original.Expires, unmarshaled.Expires, time.Second)
}

func TestBrowserCookie_Expiry(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		s := BrowserCookie{
			Email:    "user@example.com",
			Provider: "google",
			Expires:  time.Now().Add(1 * time.Hour),
		}
		assert.True(t, s.Expires.After(time.Now()))
	})

	t.Run("expired", func(t *testing.T) {
		s := BrowserCookie{
			Email:    "user@example.com",
			Provider: "google",
			Expires:  time.Now().Add(-1 * time.Hour),
		}
		assert.True(t, s.Expires.Before(time.Now()))
	})
}

func TestAuthorizationState_MarshalUnmarshal(t *testing.T) {
	original := AuthorizationState{
		Nonce:     "test-nonce-value",
		ReturnURL: "/my/tokens",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var unmarshaled AuthorizationState
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.Nonce, unmarshaled.Nonce)
	assert.Equal(t, original.ReturnURL, unmarshaled.ReturnURL)
}
