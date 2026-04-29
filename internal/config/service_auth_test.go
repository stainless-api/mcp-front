package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAuth_UnmarshalJSON_BearerValidation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   string
		wantValid bool
	}{
		{
			name:      "valid bearer with one token",
			input:     `{"type":"bearer","tokens":["t1"]}`,
			wantValid: true,
		},
		{
			name:      "valid bearer with multiple tokens",
			input:     `{"type":"bearer","tokens":["t1","t2","t3"]}`,
			wantValid: true,
		},
		{
			name:    "missing tokens field",
			input:   `{"type":"bearer"}`,
			wantErr: "at least one token is required",
		},
		{
			name:    "empty tokens array",
			input:   `{"type":"bearer","tokens":[]}`,
			wantErr: "at least one token is required",
		},
		{
			name:    "empty string as the only token",
			input:   `{"type":"bearer","tokens":[""]}`,
			wantErr: "bearer auth token at index 0 cannot be empty",
		},
		{
			name:    "empty string mixed with valid tokens",
			input:   `{"type":"bearer","tokens":["valid","","also-valid"]}`,
			wantErr: "bearer auth token at index 1 cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sa ServiceAuth
			err := json.Unmarshal([]byte(tt.input), &sa)
			if tt.wantValid {
				require.NoError(t, err)
				assert.Equal(t, ServiceAuthTypeBearer, sa.Type)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
