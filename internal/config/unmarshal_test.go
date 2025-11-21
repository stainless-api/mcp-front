package config

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigValue(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		envVars       map[string]string
		expectedValue string
		expectedToken bool
		expectedError bool
	}{
		{
			name:          "plain string",
			input:         `"hello world"`,
			expectedValue: "hello world",
			expectedToken: false,
		},
		{
			name:          "env reference",
			input:         `{"$env": "TEST_VAR"}`,
			envVars:       map[string]string{"TEST_VAR": "test value"},
			expectedValue: "test value",
			expectedToken: false,
		},
		{
			name:          "env reference with double quotes",
			input:         `{"$env": "QUOTED_VAR"}`,
			envVars:       map[string]string{"QUOTED_VAR": `"quoted value"`},
			expectedValue: "quoted value",
			expectedToken: false,
		},
		{
			name:          "env reference with single quotes",
			input:         `{"$env": "SINGLE_QUOTED"}`,
			envVars:       map[string]string{"SINGLE_QUOTED": `'single quoted'`},
			expectedValue: "single quoted",
			expectedToken: false,
		},
		{
			name:          "env reference with mixed quotes not stripped",
			input:         `{"$env": "MIXED_QUOTES"}`,
			envVars:       map[string]string{"MIXED_QUOTES": `"mixed quotes'`},
			expectedValue: `"mixed quotes'`,
			expectedToken: false,
		},
		{
			name:          "env reference with no surrounding quotes",
			input:         `{"$env": "NO_QUOTES"}`,
			envVars:       map[string]string{"NO_QUOTES": `no quotes`},
			expectedValue: "no quotes",
			expectedToken: false,
		},
		{
			name:          "env reference with internal quotes preserved",
			input:         `{"$env": "INTERNAL_QUOTES"}`,
			envVars:       map[string]string{"INTERNAL_QUOTES": `"value with "internal" quotes"`},
			expectedValue: `value with "internal" quotes`,
			expectedToken: false,
		},
		{
			name:          "missing env var",
			input:         `{"$env": "MISSING_VAR"}`,
			expectedError: true,
		},
		{
			name:          "user token reference",
			input:         `{"$userToken": "Bearer {{token}}"}`,
			expectedValue: "Bearer {{token}}",
			expectedToken: true,
		},
		{
			name:          "invalid reference type",
			input:         `{"$unknown": "value"}`,
			expectedError: true,
		},
		{
			name:          "number instead of string",
			input:         `123`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			var raw json.RawMessage = []byte(tt.input)
			result, err := ParseConfigValue(raw)

			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedValue, result.value)
			assert.Equal(t, tt.expectedToken, result.needsUserToken)
		})
	}
}

func TestMCPClientConfig_UnmarshalJSON(t *testing.T) {
	// Set up test env vars
	os.Setenv("TEST_IMAGE", "mcp/test:latest")
	os.Setenv("API_URL", "https://api.example.com")
	defer os.Unsetenv("TEST_IMAGE")
	defer os.Unsetenv("API_URL")

	input := `{
		"transportType": "stdio",
		"command": "docker",
		"args": ["run", {"$env": "TEST_IMAGE"}, {"$userToken": "--token={{token}}"}],
		"env": {
			"API_ENDPOINT": {"$env": "API_URL"},
			"AUTH_HEADER": {"$userToken": "Bearer {{token}}"}
		},
		"requiresUserToken": true,
		"userAuthentication": {
			"type": "manual",
			"displayName": "Test Token",
			"instructions": "Enter your test token",
			"validation": "^test_[a-z]+$"
		}
	}`

	var config MCPClientConfig
	err := json.Unmarshal([]byte(input), &config)
	require.NoError(t, err)

	// Check resolved values
	assert.Equal(t, "docker", config.Command)
	assert.Equal(t, []string{"run", "mcp/test:latest", "--token={{token}}"}, config.Args)
	assert.Equal(t, map[string]string{
		"API_ENDPOINT": "https://api.example.com",
		"AUTH_HEADER":  "Bearer {{token}}",
	}, config.Env)

	// Check tracking maps
	assert.Equal(t, []bool{false, false, true}, config.ArgsNeedToken)
	assert.Equal(t, map[string]bool{
		"API_ENDPOINT": false,
		"AUTH_HEADER":  true,
	}, config.EnvNeedsToken)

	// Check user authentication
	assert.True(t, config.RequiresUserToken)
	assert.NotNil(t, config.UserAuthentication)
	assert.Equal(t, UserAuthTypeManual, config.UserAuthentication.Type)
	assert.Equal(t, "Test Token", config.UserAuthentication.DisplayName)
	assert.NotNil(t, config.UserAuthentication.ValidationRegex)
	assert.True(t, config.UserAuthentication.ValidationRegex.MatchString("test_abc"))
	assert.False(t, config.UserAuthentication.ValidationRegex.MatchString("test_123"))
}

func TestMCPClientConfig_ApplyUserToken(t *testing.T) {
	config := &MCPClientConfig{
		Command: "docker",
		Args:    []string{"run", "mcp/notion", "--token={{token}}"},
		Env: map[string]string{
			"API_URL":     "https://api.notion.com",
			"AUTH_HEADER": "Bearer {{token}}",
		},
		ArgsNeedToken: []bool{false, false, true},
		EnvNeedsToken: map[string]bool{
			"API_URL":     false,
			"AUTH_HEADER": true,
		},
		RequiresUserToken: true,
	}

	// Apply user token
	result := config.ApplyUserToken("secret_abc123")

	// Original should be unchanged
	assert.Equal(t, "Bearer {{token}}", config.Env["AUTH_HEADER"])
	assert.Equal(t, "--token={{token}}", config.Args[2])

	// Result should have substitutions
	assert.Equal(t, "Bearer secret_abc123", result.Env["AUTH_HEADER"])
	assert.Equal(t, "--token=secret_abc123", result.Args[2])
	assert.Equal(t, "https://api.notion.com", result.Env["API_URL"]) // unchanged

	// Tracking maps should be cleared in result
	assert.Nil(t, result.EnvNeedsToken)
	assert.Nil(t, result.ArgsNeedToken)
}

func TestApplyUserToken_SSE(t *testing.T) {
	// Test SSE/HTTP config with user tokens in URL and headers
	jsonStr := `{
		"transportType": "sse",
		"url": {"$userToken": "https://api.example.com/mcp?token={{token}}"},
		"headers": {
			"Authorization": {"$userToken": "Bearer {{token}}"},
			"X-API-Version": "v1"
		},
		"requiresUserToken": true
	}`

	var config MCPClientConfig
	err := json.Unmarshal([]byte(jsonStr), &config)
	require.NoError(t, err)

	// Check parsed values
	assert.Equal(t, "https://api.example.com/mcp?token={{token}}", config.URL)
	assert.True(t, config.URLNeedsToken)
	assert.Equal(t, "Bearer {{token}}", config.Headers["Authorization"])
	assert.Equal(t, "v1", config.Headers["X-API-Version"])
	assert.True(t, config.HeadersNeedToken["Authorization"])
	assert.False(t, config.HeadersNeedToken["X-API-Version"])

	// Apply token
	result := config.ApplyUserToken("test-token-123")

	// Check substitutions
	assert.Equal(t, "https://api.example.com/mcp?token=test-token-123", result.URL)
	assert.Equal(t, "Bearer test-token-123", result.Headers["Authorization"])
	assert.Equal(t, "v1", result.Headers["X-API-Version"]) // unchanged

	// Tracking should be cleared
	assert.False(t, result.URLNeedsToken)
	assert.Nil(t, result.HeadersNeedToken)
}

func TestOAuthAuthConfig_UnmarshalJSON(t *testing.T) {
	// Set up test env vars
	os.Setenv("CLIENT_SECRET", "test-secret-value")
	os.Setenv("JWT_SECRET", "this-is-a-very-long-jwt-secret-key")
	os.Setenv("ENCRYPTION_KEY", "exactly-32-bytes-long-encryptkey")
	defer func() {
		os.Unsetenv("CLIENT_SECRET")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("ENCRYPTION_KEY")
	}()

	input := `{
		"kind": "oauth",
		"issuer": "https://example.com",
		"gcpProject": "test-project",
		"allowedDomains": ["example.com"],
		"allowedOrigins": ["https://claude.ai", "https://example.com"],
		"tokenTtl": "1h",
		"storage": "firestore",
		"googleClientId": "test-client-id",
		"googleClientSecret": {"$env": "CLIENT_SECRET"},
		"googleRedirectUri": "https://example.com/callback",
		"jwtSecret": {"$env": "JWT_SECRET"},
		"encryptionKey": {"$env": "ENCRYPTION_KEY"}
	}`

	var config OAuthAuthConfig
	err := json.Unmarshal([]byte(input), &config)
	require.NoError(t, err)

	assert.Equal(t, AuthKindOAuth, config.Kind)
	assert.Equal(t, "https://example.com", config.Issuer)
	assert.Equal(t, "test-project", config.GCPProject)
	assert.Equal(t, []string{"example.com"}, config.AllowedDomains)
	assert.Equal(t, []string{"https://claude.ai", "https://example.com"}, config.AllowedOrigins)
	assert.Equal(t, "test-client-id", config.GoogleClientID)
	assert.Equal(t, Secret("test-secret-value"), config.GoogleClientSecret)
	assert.Equal(t, Secret("this-is-a-very-long-jwt-secret-key"), config.JWTSecret)
	assert.Equal(t, Secret("exactly-32-bytes-long-encryptkey"), config.EncryptionKey)
}

func TestOAuthAuthConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		envVars       map[string]string
		expectedError string
	}{
		{
			name: "jwt secret too short",
			input: `{
				"kind": "oauth",
				"jwtSecret": {"$env": "SHORT_SECRET"}
			}`,
			envVars:       map[string]string{"SHORT_SECRET": "too-short"},
			expectedError: "jwt secret must be at least 32 bytes",
		},
		{
			name: "user token in oauth field",
			input: `{
				"kind": "oauth",
				"jwtSecret": {"$userToken": "{{token}}"}
			}`,
			expectedError: "jwtSecret cannot be a user token reference",
		},
		{
			name: "encryption key wrong length",
			input: `{
				"kind": "oauth",
				"storage": "firestore",
				"jwtSecret": {"$env": "JWT_SECRET"},
				"encryptionKey": {"$env": "BAD_KEY"}
			}`,
			envVars: map[string]string{
				"JWT_SECRET": "this-is-a-very-long-jwt-secret-key",
				"BAD_KEY":    "wrong-length",
			},
			expectedError: "encryption key must be exactly 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			var config OAuthAuthConfig
			err := json.Unmarshal([]byte(tt.input), &config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestSessionConfig_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedTimeout time.Duration
		expectedCleanup time.Duration
		expectedError   bool
	}{
		{
			name: "valid durations",
			input: `{
				"timeout": "10m",
				"cleanupInterval": "2m"
			}`,
			expectedTimeout: 10 * time.Minute,
			expectedCleanup: 2 * time.Minute,
		},
		{
			name: "empty strings",
			input: `{
				"timeout": "",
				"cleanupInterval": ""
			}`,
			expectedTimeout: 0,
			expectedCleanup: 0,
		},
		{
			name:            "missing fields",
			input:           `{}`,
			expectedTimeout: 0,
			expectedCleanup: 0,
		},
		{
			name: "invalid duration format",
			input: `{
				"timeout": "invalid",
				"cleanupInterval": "2m"
			}`,
			expectedError: true,
		},
		{
			name: "numeric values rejected",
			input: `{
				"timeout": 600000000000,
				"cleanupInterval": 120000000000
			}`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config SessionConfig
			err := json.Unmarshal([]byte(tt.input), &config)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedTimeout, config.Timeout)
				assert.Equal(t, tt.expectedCleanup, config.CleanupInterval)
			}
		})
	}
}

func TestProxyConfig_SessionConfigIntegration(t *testing.T) {
	input := `{
		"baseURL": "http://localhost:8080",
		"addr": ":8080",
		"auth": {
			"kind": "oauth",
			"issuer": "https://auth.example.com",
			"googleClientId": "test-client",
			"googleClientSecret": "test-secret",
			"googleRedirectUri": "https://test.example.com/callback",
			"jwtSecret": "test-jwt-secret-must-be-32-bytes-long",
			"encryptionKey": "test-encryption-key-32-bytes-ok!",
			"allowedDomains": ["example.com"],
			"allowedOrigins": ["https://test.example.com"]
		},
		"sessions": {
			"timeout": "15m",
			"cleanupInterval": "3m"
		}
	}`

	var config ProxyConfig
	err := json.Unmarshal([]byte(input), &config)
	require.NoError(t, err)

	require.NotNil(t, config.Sessions)
	assert.Equal(t, 15*time.Minute, config.Sessions.Timeout)
	assert.Equal(t, 3*time.Minute, config.Sessions.CleanupInterval)
}
