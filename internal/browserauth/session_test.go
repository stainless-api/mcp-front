package browserauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionCookie_MarshalUnmarshal(t *testing.T) {
	original := SessionCookie{
		Email:   "user@example.com",
		Expires: time.Now().Add(24 * time.Hour).Truncate(time.Second),
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var unmarshaled SessionCookie
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	// Truncate for comparison (JSON time serialization)
	assert.Equal(t, original.Email, unmarshaled.Email)
	assert.WithinDuration(t, original.Expires, unmarshaled.Expires, time.Second)
}

func TestSessionCookie_Expiry(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		session := SessionCookie{
			Email:   "user@example.com",
			Expires: time.Now().Add(1 * time.Hour),
		}

		assert.True(t, session.Expires.After(time.Now()))
	})

	t.Run("expired", func(t *testing.T) {
		session := SessionCookie{
			Email:   "user@example.com",
			Expires: time.Now().Add(-1 * time.Hour),
		}

		assert.True(t, session.Expires.Before(time.Now()))
	})
}

func TestAuthorizationState_MarshalUnmarshal(t *testing.T) {
	original := AuthorizationState{
		Nonce:     "test-nonce-value",
		ReturnURL: "/my/tokens",
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var unmarshaled AuthorizationState
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.Nonce, unmarshaled.Nonce)
	assert.Equal(t, original.ReturnURL, unmarshaled.ReturnURL)
}
