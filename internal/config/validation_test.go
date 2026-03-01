package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateFile(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		wantErrors    []string
		wantWarnings  []string
		wantErrCount  int
		wantWarnCount int
	}{
		{
			name: "valid_service_auth_config",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio",
						"command": "docker",
						"serviceAuths": [{
							"type": "bearer",
							"tokens": ["token1"]
						}]
					}
				}
			}`,
			wantErrCount:  0,
			wantWarnCount: 0,
		},
		{
			name: "valid_oauth_config",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth",
						"issuer": "https://example.com",
						"idp": {
							"provider": "google",
							"clientId": {"$env": "CLIENT_ID"},
							"clientSecret": {"$env": "CLIENT_SECRET"},
							"redirectUri": "https://example.com/callback"
						},
						"jwtSecret": {"$env": "JWT_SECRET"},
						"encryptionKey": {"$env": "ENCRYPTION_KEY"},
						"allowedDomains": ["example.com"],
						"allowedOrigins": ["https://claude.ai"]
					}
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio",
						"command": "docker"
					}
				}
			}`,
			wantErrCount:  0,
			wantWarnCount: 0,
		},
		{
			name: "missing_version",
			config: `{
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {}
			}`,
			wantErrors:   []string{"version field is required. Hint: Add \"version\": \"v0.0.1-DEV_EDITION\""},
			wantErrCount: 1,
		},
		{
			name: "invalid_version",
			config: `{
				"version": "v2.0.0",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {}
			}`,
			wantErrors:   []string{"unsupported version 'v2.0.0' - use 'v0.0.1-DEV_EDITION' or 'v0.0.1-DEV_EDITION-<variant>'"},
			wantErrCount: 1,
		},
		{
			name: "missing_proxy",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"mcpServers": {}
			}`,
			wantErrors:   []string{"proxy field is required and must be an object"},
			wantErrCount: 1,
		},
		{
			name: "missing_proxy_fields",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {},
				"mcpServers": {}
			}`,
			wantErrors: []string{
				"baseURL is required. Example: \"https://api.example.com\"",
				"addr is required. Example: \":8080\" or \"0.0.0.0:8080\"",
			},
			wantErrCount: 2,
		},
		{
			name: "bash_style_env_vars",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "$BASE_URL",
					"addr": "${ADDR}"
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio",
						"command": "docker",
						"env": {
							"DB_URL": "${DATABASE_URL}"
						}
					}
				}
			}`,
			wantWarnings: []string{
				"found bash-style syntax '$BASE_URL'",
				"found bash-style syntax '${ADDR}'",
				"found bash-style syntax '${DATABASE_URL}'",
			},
			wantWarnCount: 3,
		},
		{
			name: "missing_transport_type",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"postgres": {
						"command": "docker"
					}
				}
			}`,
			wantErrors:   []string{"transportType is required. Options: stdio, sse, streamable-http, inline"},
			wantErrCount: 1,
		},
		{
			name: "stdio_missing_command",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio"
					}
				}
			}`,
			wantErrors:   []string{"command is required for stdio transport. Example: [\"npx\", \"-y\", \"@your/mcp-server\"]"},
			wantErrCount: 1,
		},
		{
			name: "sse_missing_url",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"api": {
						"transportType": "sse"
					}
				}
			}`,
			wantErrors:   []string{"url is required for sse transport"},
			wantErrCount: 1,
		},
		{
			name: "user_token_without_oauth",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"notion": {
						"transportType": "stdio",
						"command": "docker",
						"requiresUserToken": true
					}
				}
			}`,
			wantErrors: []string{
				"server requires user token but OAuth is not configured. Hint: User tokens require OAuth authentication - set proxy.auth.kind to 'oauth'",
				"userAuthentication is required when requiresUserToken is true. Hint: Add userAuthentication with type, displayName and instructions",
			},
			wantErrCount: 2,
		},
		{
			name: "user_token_missing_setup",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth",
						"issuer": "https://example.com",
						"idp": {
							"provider": "google",
							"clientId": "id",
							"clientSecret": "secret",
							"redirectUri": "https://example.com/callback"
						},
						"jwtSecret": "secret",
						"encryptionKey": "key",
						"allowedDomains": ["example.com"],
						"allowedOrigins": ["https://claude.ai"]
					}
				},
				"mcpServers": {
					"notion": {
						"transportType": "stdio",
						"command": "docker",
						"requiresUserToken": true
					}
				}
			}`,
			wantErrors:   []string{"userAuthentication is required when requiresUserToken is true. Hint: Add userAuthentication with type, displayName and instructions"},
			wantErrCount: 1,
		},
		{
			name: "oauth_missing_fields",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth"
					}
				},
				"mcpServers": {}
			}`,
			wantErrors: []string{
				"issuer is required for OAuth",
				"jwtSecret is required for OAuth. Hint: Must be at least 32 bytes long for HMAC-SHA256",
				"encryptionKey is required for OAuth. Hint: Must be exactly 32 bytes for AES-256-GCM encryption",
				"idp configuration is required for OAuth",
				"at least one allowed origin is required for OAuth (CORS configuration)",
			},
			wantErrCount: 5,
		},
		{
			name: "valid_manual_user_authentication",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth",
						"issuer": "https://example.com",
						"idp": {
							"provider": "google",
							"clientId": "id",
							"clientSecret": "secret",
							"redirectUri": "https://example.com/callback"
						},
						"jwtSecret": "secret123456789012345678901234567890",
						"encryptionKey": "key12345678901234567890123456789",
						"allowedDomains": ["example.com"],
						"allowedOrigins": ["https://claude.ai"]
					}
				},
				"mcpServers": {
					"notion": {
						"transportType": "stdio",
						"command": "docker",
						"requiresUserToken": true,
						"userAuthentication": {
							"type": "manual",
							"displayName": "Notion",
							"instructions": "Get your token from Notion settings"
						}
					}
				}
			}`,
			wantErrors:   []string{},
			wantErrCount: 0,
		},
		{
			name: "valid_oauth_user_authentication",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth",
						"issuer": "https://example.com",
						"idp": {
							"provider": "google",
							"clientId": "id",
							"clientSecret": "secret",
							"redirectUri": "https://example.com/callback"
						},
						"jwtSecret": "secret123456789012345678901234567890",
						"encryptionKey": "key12345678901234567890123456789",
						"allowedDomains": ["example.com"],
						"allowedOrigins": ["https://claude.ai"]
					}
				},
				"mcpServers": {
					"linear": {
						"transportType": "stdio",
						"command": "npx",
						"requiresUserToken": true,
						"userAuthentication": {
							"type": "oauth",
							"displayName": "Linear",
							"clientId": "client123",
							"clientSecret": {"$env": "LINEAR_CLIENT_SECRET"},
							"authorizationUrl": "https://linear.app/oauth/authorize",
							"tokenUrl": "https://api.linear.app/oauth/token",
							"scopes": ["read", "write"]
						}
					}
				}
			}`,
			wantErrors:   []string{},
			wantErrCount: 0,
		},
		{
			name: "invalid_oauth_user_authentication_missing_fields",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth",
						"issuer": "https://example.com",
						"idp": {
							"provider": "google",
							"clientId": "id",
							"clientSecret": "secret",
							"redirectUri": "https://example.com/callback"
						},
						"jwtSecret": "secret123456789012345678901234567890",
						"encryptionKey": "key12345678901234567890123456789",
						"allowedDomains": ["example.com"],
						"allowedOrigins": ["https://claude.ai"]
					}
				},
				"mcpServers": {
					"linear": {
						"transportType": "stdio",
						"command": "npx",
						"requiresUserToken": true,
						"userAuthentication": {
							"type": "oauth",
							"displayName": "Linear",
							"clientId": "client123"
						}
					}
				}
			}`,
			wantErrors: []string{
				"authorizationUrl is required for OAuth configuration",
				"tokenUrl is required for OAuth configuration",
				"scopes is required for OAuth configuration",
				"scopes must be an array",
				"clientSecret is required for OAuth configuration",
			},
			wantErrCount: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.json")
			err := os.WriteFile(configPath, []byte(tt.config), 0644)
			require.NoError(t, err)

			// Validate
			result, err := ValidateFile(configPath)
			assert.NoError(t, err)
			assert.NotNil(t, result)

			// Check error count
			assert.Equal(t, tt.wantErrCount, len(result.Errors),
				"expected %d errors but got %d: %v", tt.wantErrCount, len(result.Errors), result.Errors)

			// Check warning count
			assert.Equal(t, tt.wantWarnCount, len(result.Warnings),
				"expected %d warnings but got %d: %v", tt.wantWarnCount, len(result.Warnings), result.Warnings)

			// Check specific errors
			for _, wantErr := range tt.wantErrors {
				found := false
				for _, err := range result.Errors {
					if err.Message == wantErr {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error '%s' not found in %v", wantErr, result.Errors)
			}

			// Check specific warnings
			for _, wantWarn := range tt.wantWarnings {
				found := false
				for _, warn := range result.Warnings {
					if warn.Message != "" && contains(warn.Message, wantWarn) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected warning containing '%s' not found in %v", wantWarn, result.Warnings)
			}
		})
	}
}

func TestValidateFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	err := os.WriteFile(configPath, []byte(`{invalid json`), 0644)
	require.NoError(t, err)

	result, err := ValidateFile(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Errors))
	assert.Contains(t, result.Errors[0].Message, "invalid JSON")
}

func TestValidateFile_FileNotFound(t *testing.T) {
	result, err := ValidateFile("/nonexistent/file.json")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "reading config file")
}

func TestValidateFile_ImprovedErrorMessages(t *testing.T) {
	tests := []struct {
		name         string
		config       string
		wantErrorMsg string
	}{
		{
			name: "plain_text_password",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"service": {
						"transportType": "stdio",
						"command": "test",
						"serviceAuths": [{
							"type": "basic",
							"username": "user",
							"password": "my-secret-password"
						}]
					}
				}
			}`,
			wantErrorMsg: "password must use environment variable reference {\"$env\": \"YOUR_ENV_VAR\"} instead of plain text 'my-secret-password'",
		},
		{
			name: "bash_style_password",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"service": {
						"transportType": "stdio",
						"command": "test",
						"serviceAuths": [{
							"type": "basic",
							"username": "user",
							"password": "$DB_PASSWORD"
						}]
					}
				}
			}`,
			wantErrorMsg: "found bash-style syntax '$DB_PASSWORD' - use {\"$env\": \"DB_PASSWORD\"} instead",
		},
		{
			name: "plain_text_clientSecret",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080",
					"auth": {
						"kind": "oauth",
						"issuer": "https://example.com",
						"idp": {
							"provider": "google",
							"clientId": "id",
							"clientSecret": "secret",
							"redirectUri": "https://example.com/callback"
						},
						"jwtSecret": "secret123456789012345678901234567890",
						"encryptionKey": "key12345678901234567890123456789",
						"allowedDomains": ["example.com"],
						"allowedOrigins": ["https://claude.ai"]
					}
				},
				"mcpServers": {
					"linear": {
						"transportType": "stdio",
						"command": "npx",
						"requiresUserToken": true,
						"userAuthentication": {
							"type": "oauth",
							"displayName": "Linear",
							"clientId": "client123",
							"clientSecret": "super-secret",
							"authorizationUrl": "https://linear.app/oauth/authorize",
							"tokenUrl": "https://api.linear.app/oauth/token",
							"scopes": ["read"]
						}
					}
				}
			}`,
			wantErrorMsg: "clientSecret must use environment variable reference {\"$env\": \"YOUR_ENV_VAR\"} instead of plain text 'super-secret'",
		},
		{
			name: "bash_style_userToken",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"service": {
						"transportType": "stdio",
						"command": "test",
						"requiresUserToken": true,
						"serviceAuths": [{
							"type": "basic",
							"username": "user",
							"password": {"$env": "PASS"},
							"userToken": "${USER_TOKEN}"
						}]
					}
				}
			}`,
			wantErrorMsg: "userToken must use {\"$userToken\": \"{{token}}\"} format instead of plain text '${USER_TOKEN}'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.json")
			err := os.WriteFile(configPath, []byte(tt.config), 0644)
			require.NoError(t, err)

			// Validate
			result, err := ValidateFile(configPath)
			assert.NoError(t, err)
			assert.NotNil(t, result)

			// Check that we have at least one error
			assert.GreaterOrEqual(t, len(result.Errors), 1, "Expected at least one validation error")

			// Check that one of the errors contains our expected message
			found := false
			for _, e := range result.Errors {
				if strings.Contains(e.Message, tt.wantErrorMsg) {
					found = true
					break
				}
			}
			assert.True(t, found, "Expected error message containing '%s', but got errors: %v", tt.wantErrorMsg, result.Errors)
		})
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestValidateFile_AggregateServer(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		wantErrors []string
	}{
		{
			name: "valid_aggregate",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"postgres": {
						"transportType": "stdio",
						"command": "pg-mcp"
					},
					"mcp": {
						"type": "aggregate",
						"servers": ["postgres"]
					}
				}
			}`,
			wantErrors: nil,
		},
		{
			name: "server_name_with_dot",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"my.server": {
						"transportType": "stdio",
						"command": "test"
					}
				}
			}`,
			wantErrors: []string{"cannot contain '.'"},
		},
		{
			name: "aggregate_rejects_direct_fields",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"mcp": {
						"type": "aggregate",
						"command": "test",
						"url": "http://localhost"
					}
				}
			}`,
			wantErrors: []string{"command is not allowed on aggregate", "url is not allowed on aggregate"},
		},
		{
			name: "aggregate_self_reference",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"mcp": {
						"type": "aggregate",
						"servers": ["mcp"]
					}
				}
			}`,
			wantErrors: []string{"cannot reference itself"},
		},
		{
			name: "aggregate_references_other_aggregate",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"agg1": {
						"type": "aggregate"
					},
					"agg2": {
						"type": "aggregate",
						"servers": ["agg1"]
					}
				}
			}`,
			wantErrors: []string{"cannot reference another aggregate"},
		},
		{
			name: "aggregate_references_nonexistent",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"mcp": {
						"type": "aggregate",
						"servers": ["nonexistent"]
					}
				}
			}`,
			wantErrors: []string{"does not exist"},
		},
		{
			name: "aggregate_invalid_transport",
			config: `{
				"version": "v0.0.1-DEV_EDITION",
				"proxy": {
					"baseURL": "http://localhost:8080",
					"addr": ":8080"
				},
				"mcpServers": {
					"mcp": {
						"type": "aggregate",
						"transportType": "stdio"
					}
				}
			}`,
			wantErrors: []string{"only support 'sse' or 'streamable-http'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(tmpFile, []byte(tt.config), 0644))

			result, err := ValidateFile(tmpFile)
			require.NoError(t, err)

			if tt.wantErrors == nil {
				assert.True(t, result.IsValid(), "Expected no errors, got: %v", result.Errors)
			} else {
				for _, wantErr := range tt.wantErrors {
					found := false
					for _, gotErr := range result.Errors {
						if strings.Contains(gotErr.Message, wantErr) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error containing '%s', got: %v", wantErr, result.Errors)
				}
			}
		})
	}
}
