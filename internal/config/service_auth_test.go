package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAuth_UnmarshalJSON_BasicValidation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   string
		wantValid bool
		// when wantValid is true and wantName is set, assert that ServiceAuth.Name resolved to this value
		wantName string
	}{
		{
			name:      "valid basic auth — name defaults to username",
			input:     `{"type":"basic","username":"alice","password":"hunter2"}`,
			wantValid: true,
			wantName:  "alice",
		},
		{
			name:      "valid basic auth — explicit name overrides username",
			input:     `{"type":"basic","username":"alice","name":"alice-readonly","password":"hunter2"}`,
			wantValid: true,
			wantName:  "alice-readonly",
		},
		{
			name:      "name lowercased",
			input:     `{"type":"basic","username":"Alice","password":"hunter2"}`,
			wantValid: true,
			wantName:  "alice",
		},
		{
			name:    "empty password string",
			input:   `{"type":"basic","username":"alice","password":""}`,
			wantErr: "basic auth password cannot be empty",
		},
		{
			name:    "missing password field",
			input:   `{"type":"basic","username":"alice"}`,
			wantErr: "password is required for basic auth",
		},
		{
			name:    "missing username",
			input:   `{"type":"basic","password":"hunter2"}`,
			wantErr: "username is required for basic auth",
		},
		{
			name:    "name with @ rejected",
			input:   `{"type":"basic","username":"alice","name":"al@ice","password":"hunter2"}`,
			wantErr: "service auth name",
		},
		{
			name:    "name with dot rejected",
			input:   `{"type":"basic","username":"alice","name":"al.ice","password":"hunter2"}`,
			wantErr: "service auth name",
		},
		{
			name:    "name with whitespace rejected",
			input:   `{"type":"basic","username":"alice","name":"al ice","password":"hunter2"}`,
			wantErr: "service auth name",
		},
		{
			name:    "name with leading hyphen rejected",
			input:   `{"type":"basic","username":"alice","name":"-alice","password":"hunter2"}`,
			wantErr: "service auth name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sa ServiceAuth
			err := json.Unmarshal([]byte(tt.input), &sa)
			if tt.wantValid {
				require.NoError(t, err)
				assert.Equal(t, ServiceAuthTypeBasic, sa.Type)
				if tt.wantName != "" {
					assert.Equal(t, tt.wantName, sa.Name)
				}
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestServiceAuth_UnmarshalJSON_BearerValidation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   string
		wantValid bool
		wantName  string
	}{
		{
			name:      "valid bearer with one token + explicit name",
			input:     `{"type":"bearer","name":"ci","tokens":["t1"]}`,
			wantValid: true,
			wantName:  "ci",
		},
		{
			name:      "valid bearer with multiple tokens",
			input:     `{"type":"bearer","name":"ci","tokens":["t1","t2","t3"]}`,
			wantValid: true,
			wantName:  "ci",
		},
		{
			name:      "name lowercased",
			input:     `{"type":"bearer","name":"CI","tokens":["t1"]}`,
			wantValid: true,
			wantName:  "ci",
		},
		{
			name:    "missing name",
			input:   `{"type":"bearer","tokens":["t1"]}`,
			wantErr: "bearer auth requires a `name`",
		},
		{
			name:    "missing tokens field",
			input:   `{"type":"bearer","name":"ci"}`,
			wantErr: "at least one token is required",
		},
		{
			name:    "empty tokens array",
			input:   `{"type":"bearer","name":"ci","tokens":[]}`,
			wantErr: "at least one token is required",
		},
		{
			name:    "empty string as the only token",
			input:   `{"type":"bearer","name":"ci","tokens":[""]}`,
			wantErr: "bearer auth token at index 0 cannot be empty",
		},
		{
			name:    "empty string mixed with valid tokens",
			input:   `{"type":"bearer","name":"ci","tokens":["valid","","also-valid"]}`,
			wantErr: "bearer auth token at index 1 cannot be empty",
		},
		{
			name:    "name with invalid char",
			input:   `{"type":"bearer","name":"ci@runner","tokens":["t1"]}`,
			wantErr: "service auth name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sa ServiceAuth
			err := json.Unmarshal([]byte(tt.input), &sa)
			if tt.wantValid {
				require.NoError(t, err)
				assert.Equal(t, ServiceAuthTypeBearer, sa.Type)
				if tt.wantName != "" {
					assert.Equal(t, tt.wantName, sa.Name)
				}
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestMCPClientConfig_ServiceAuth_Uniqueness(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "two basic with same username collide",
			input: `{
				"transportType": "stdio", "command": "x",
				"serviceAuths": [
					{"type":"basic","username":"admin","password":"p1"},
					{"type":"basic","username":"admin","password":"p2"}
				]
			}`,
			wantErr: `both resolve to identity name "admin"`,
		},
		{
			name: "two bearer with same name collide",
			input: `{
				"transportType": "stdio", "command": "x",
				"serviceAuths": [
					{"type":"bearer","name":"ci","tokens":["t1"]},
					{"type":"bearer","name":"ci","tokens":["t2"]}
				]
			}`,
			wantErr: `both resolve to identity name "ci"`,
		},
		{
			name: "basic and bearer with same name collide",
			input: `{
				"transportType": "stdio", "command": "x",
				"serviceAuths": [
					{"type":"basic","username":"alice","password":"p"},
					{"type":"bearer","name":"alice","tokens":["t1"]}
				]
			}`,
			wantErr: `both resolve to identity name "alice"`,
		},
		{
			name: "basic explicit name collides with bearer name",
			input: `{
				"transportType": "stdio", "command": "x",
				"serviceAuths": [
					{"type":"basic","username":"u","name":"shared","password":"p"},
					{"type":"bearer","name":"shared","tokens":["t1"]}
				]
			}`,
			wantErr: `both resolve to identity name "shared"`,
		},
		{
			name: "case-insensitive collision",
			input: `{
				"transportType": "stdio", "command": "x",
				"serviceAuths": [
					{"type":"basic","username":"admin","password":"p"},
					{"type":"bearer","name":"ADMIN","tokens":["t1"]}
				]
			}`,
			wantErr: `both resolve to identity name "admin"`,
		},
		{
			name: "different names succeed",
			input: `{
				"transportType": "stdio", "command": "x",
				"serviceAuths": [
					{"type":"basic","username":"alice","password":"p"},
					{"type":"bearer","name":"ci","tokens":["t1"]}
				]
			}`,
			wantErr: "",
		},
		{
			name: "two basic with same username and distinct names",
			input: `{
				"transportType": "stdio", "command": "x",
				"serviceAuths": [
					{"type":"basic","username":"alice","password":"pw1","name":"alice-readonly"},
					{"type":"basic","username":"alice","password":"pw2","name":"alice-admin"}
				]
			}`,
			wantErr: `basic auth username "alice" already used by serviceAuths[0]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c MCPClientConfig
			err := json.Unmarshal([]byte(tt.input), &c)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
