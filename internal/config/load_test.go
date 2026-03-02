package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateConfig_UserTokensRequireOAuth(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError string
	}{
		{
			name: "user_tokens_without_oauth",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"notion": {
						TransportType:     MCPClientTypeSSE,
						URL:               "https://notion.example.com",
						RequiresUserToken: true,
						UserAuthentication: &UserAuthentication{
							Type:        UserAuthTypeManual,
							DisplayName: "Notion",
						},
					},
				},
			},
			expectError: "server notion requires user tokens but OAuth is not configured",
		},
		{
			name: "user_tokens_with_oauth",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &OAuthAuthConfig{
						Kind:   "oauth",
						Issuer: "https://auth.example.com",
						IDP: IDPConfig{
							Provider:     "google",
							ClientID:     "test-client",
							ClientSecret: "test-secret",
							RedirectURI:  "https://test.example.com/callback",
						},
						JWTSecret:       "test-jwt-secret-must-be-32-bytes-long",
						EncryptionKey:   "test-encryption-key-32-bytes-ok!",
						AllowedDomains:  []string{"example.com"},
						AllowedOrigins:  []string{"https://test.example.com"},
						TokenTTL:        time.Hour,
						RefreshTokenTTL: 30 * 24 * time.Hour,
					},
				},
				MCPServers: map[string]*MCPClientConfig{
					"notion": {
						TransportType:     MCPClientTypeSSE,
						URL:               "https://notion.example.com",
						RequiresUserToken: true,
						UserAuthentication: &UserAuthentication{
							Type:        UserAuthTypeManual,
							DisplayName: "Notion",
						},
					},
				},
			},
			expectError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConfig_SessionConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		expectError   string
		expectTimeout time.Duration
		expectCleanup time.Duration
	}{
		{
			name: "valid_session_config",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &OAuthAuthConfig{
						Kind:   "oauth",
						Issuer: "https://auth.example.com",
						IDP: IDPConfig{
							Provider:     "google",
							ClientID:     "test-client",
							ClientSecret: "test-secret",
							RedirectURI:  "https://test.example.com/callback",
						},
						JWTSecret:       "test-jwt-secret-must-be-32-bytes-long",
						EncryptionKey:   "test-encryption-key-32-bytes-ok!",
						AllowedDomains:  []string{"example.com"},
						AllowedOrigins:  []string{"https://test.example.com"},
						TokenTTL:        time.Hour,
						RefreshTokenTTL: 30 * 24 * time.Hour,
					},
					Sessions: &SessionConfig{
						Timeout:         10 * time.Minute,
						CleanupInterval: 2 * time.Minute,
					},
				},
				MCPServers: map[string]*MCPClientConfig{},
			},
			expectError:   "",
			expectTimeout: 10 * time.Minute,
			expectCleanup: 2 * time.Minute,
		},
		{
			name: "negative_timeout",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &OAuthAuthConfig{
						Kind:   "oauth",
						Issuer: "https://auth.example.com",
						IDP: IDPConfig{
							Provider:     "google",
							ClientID:     "test-client",
							ClientSecret: "test-secret",
							RedirectURI:  "https://test.example.com/callback",
						},
						JWTSecret:       "test-jwt-secret-must-be-32-bytes-long",
						EncryptionKey:   "test-encryption-key-32-bytes-ok!",
						AllowedDomains:  []string{"example.com"},
						AllowedOrigins:  []string{"https://test.example.com"},
						TokenTTL:        time.Hour,
						RefreshTokenTTL: 30 * 24 * time.Hour,
					},
					Sessions: &SessionConfig{
						Timeout:         -1 * time.Minute,
						CleanupInterval: 2 * time.Minute,
					},
				},
				MCPServers: map[string]*MCPClientConfig{},
			},
			expectError: "proxy.sessions.timeout cannot be negative",
		},
		{
			name: "negative_cleanup_interval",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &OAuthAuthConfig{
						Kind:   "oauth",
						Issuer: "https://auth.example.com",
						IDP: IDPConfig{
							Provider:     "google",
							ClientID:     "test-client",
							ClientSecret: "test-secret",
							RedirectURI:  "https://test.example.com/callback",
						},
						JWTSecret:       "test-jwt-secret-must-be-32-bytes-long",
						EncryptionKey:   "test-encryption-key-32-bytes-ok!",
						AllowedDomains:  []string{"example.com"},
						AllowedOrigins:  []string{"https://test.example.com"},
						TokenTTL:        time.Hour,
						RefreshTokenTTL: 30 * 24 * time.Hour,
					},
					Sessions: &SessionConfig{
						Timeout:         10 * time.Minute,
						CleanupInterval: -30 * time.Second,
					},
				},
				MCPServers: map[string]*MCPClientConfig{},
			},
			expectError: "proxy.sessions.cleanupInterval cannot be negative",
		},
		{
			name: "empty_session_config",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
					Auth: &OAuthAuthConfig{
						Kind:   "oauth",
						Issuer: "https://auth.example.com",
						IDP: IDPConfig{
							Provider:     "google",
							ClientID:     "test-client",
							ClientSecret: "test-secret",
							RedirectURI:  "https://test.example.com/callback",
						},
						JWTSecret:       "test-jwt-secret-must-be-32-bytes-long",
						EncryptionKey:   "test-encryption-key-32-bytes-ok!",
						AllowedDomains:  []string{"example.com"},
						AllowedOrigins:  []string{"https://test.example.com"},
						TokenTTL:        time.Hour,
						RefreshTokenTTL: 30 * 24 * time.Hour,
					},
					Sessions: &SessionConfig{
						Timeout:         0,
						CleanupInterval: 0,
					},
				},
				MCPServers: map[string]*MCPClientConfig{},
			},
			expectError:   "",
			expectTimeout: 0,
			expectCleanup: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				assert.NoError(t, err)
				if tt.config.Proxy.Sessions != nil {
					assert.Equal(t, tt.expectTimeout, tt.config.Proxy.Sessions.Timeout)
					assert.Equal(t, tt.expectCleanup, tt.config.Proxy.Sessions.CleanupInterval)
				}
			}
		})
	}
}

func TestValidateConfig_AggregateServer(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError string
	}{
		{
			name: "aggregate_defaults_servers_to_all_non_aggregates",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"postgres": {
						Type:          ServerTypeDirect,
						TransportType: MCPClientTypeSSE,
						URL:           "http://localhost:5432",
					},
					"linear": {
						Type:          ServerTypeDirect,
						TransportType: MCPClientTypeSSE,
						URL:           "http://localhost:3000",
					},
					"mcp": {
						Type:          ServerTypeAggregate,
						TransportType: MCPClientTypeSSE,
						Discovery:     &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second},
					},
				},
			},
		},
		{
			name: "aggregate_self_reference",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"mcp": {
						Type:          ServerTypeAggregate,
						TransportType: MCPClientTypeSSE,
						Discovery:     &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second},
						Servers:       []string{"mcp"},
					},
				},
			},
			expectError: "cannot reference itself",
		},
		{
			name: "aggregate_references_nonexistent",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"mcp": {
						Type:          ServerTypeAggregate,
						TransportType: MCPClientTypeSSE,
						Discovery:     &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second},
						Servers:       []string{"ghost"},
					},
				},
			},
			expectError: "references nonexistent server",
		},
		{
			name: "aggregate_invalid_transport",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"mcp": {
						Type:          ServerTypeAggregate,
						TransportType: MCPClientTypeStdio,
						Discovery:     &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second},
					},
				},
			},
			expectError: "must use 'sse' or 'streamable-http'",
		},
		{
			name: "aggregate_references_inline_server",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"tools": {
						Type:          ServerTypeDirect,
						TransportType: MCPClientTypeInline,
						InlineConfig:  []byte(`{"tools":[]}`),
					},
					"mcp": {
						Type:          ServerTypeAggregate,
						TransportType: MCPClientTypeSSE,
						Discovery:     &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second},
						Servers:       []string{"tools"},
					},
				},
			},
			expectError: "cannot reference inline server",
		},
		{
			name: "aggregate_nil_discovery",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"postgres": {
						Type:          ServerTypeDirect,
						TransportType: MCPClientTypeSSE,
						URL:           "http://localhost:5432",
					},
					"mcp": {
						Type:          ServerTypeAggregate,
						TransportType: MCPClientTypeSSE,
						Servers:       []string{"postgres"},
					},
				},
			},
			expectError: "missing discovery configuration",
		},
		{
			name: "aggregate_explicit_empty_servers",
			config: &Config{
				Proxy: ProxyConfig{
					BaseURL: "https://test.example.com",
					Addr:    ":8080",
				},
				MCPServers: map[string]*MCPClientConfig{
					"postgres": {
						Type:          ServerTypeDirect,
						TransportType: MCPClientTypeSSE,
						URL:           "http://localhost:5432",
					},
					"mcp": {
						Type:          ServerTypeAggregate,
						TransportType: MCPClientTypeSSE,
						Servers:       []string{},
						Discovery:     &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second},
					},
				},
			},
			expectError: "has no servers",
		},
		{
			name: "server_name_with_dot",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"my.server": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				},
			},
			expectError: "is invalid",
		},
		{
			name: "server_name_with_slash",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"foo/bar": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				},
			},
			expectError: "is invalid",
		},
		{
			name: "server_name_with_space",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"my server": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				},
			},
			expectError: "is invalid",
		},
		{
			name: "server_name_starting_with_hyphen",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"-postgres": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				},
			},
			expectError: "is invalid",
		},
		{
			name: "valid_server_name_with_hyphen_and_underscore",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"my-server_01": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				},
			},
		},
		{
			name: "aggregate_duplicate_reference",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"postgres": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
					"mcp": {
						Type: ServerTypeAggregate, TransportType: MCPClientTypeSSE,
						Discovery: &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second},
						Servers:   []string{"postgres", "postgres"},
					},
				},
			},
			expectError: "duplicate reference 'postgres'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ResolveDefaults(tt.config)
			err := ValidateConfig(tt.config)
			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestResolveDefaults(t *testing.T) {
	t.Run("fills_aggregate_servers_with_all_non_aggregates", func(t *testing.T) {
		cfg := &Config{
			MCPServers: map[string]*MCPClientConfig{
				"postgres": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				"linear":   {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:3000"},
				"mcp":      {Type: ServerTypeAggregate, TransportType: MCPClientTypeSSE, Discovery: &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second}},
			},
		}
		ResolveDefaults(cfg)

		mcp := cfg.MCPServers["mcp"]
		assert.Equal(t, []string{"linear", "postgres"}, mcp.Servers)
	})

	t.Run("does_not_override_explicit_servers", func(t *testing.T) {
		cfg := &Config{
			MCPServers: map[string]*MCPClientConfig{
				"postgres": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				"linear":   {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:3000"},
				"mcp":      {Type: ServerTypeAggregate, TransportType: MCPClientTypeSSE, Servers: []string{"postgres"}, Discovery: &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second}},
			},
		}
		ResolveDefaults(cfg)

		mcp := cfg.MCPServers["mcp"]
		assert.Equal(t, []string{"postgres"}, mcp.Servers)
	})

	t.Run("idempotent", func(t *testing.T) {
		cfg := &Config{
			MCPServers: map[string]*MCPClientConfig{
				"postgres": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				"mcp":      {Type: ServerTypeAggregate, TransportType: MCPClientTypeSSE, Discovery: &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second}},
			},
		}
		ResolveDefaults(cfg)
		first := cfg.MCPServers["mcp"].Servers

		ResolveDefaults(cfg)
		second := cfg.MCPServers["mcp"].Servers

		assert.Equal(t, first, second)
	})

	t.Run("excludes_inline_from_defaults", func(t *testing.T) {
		cfg := &Config{
			MCPServers: map[string]*MCPClientConfig{
				"postgres": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				"tools":    {Type: ServerTypeDirect, TransportType: MCPClientTypeInline, InlineConfig: []byte(`{"tools":[]}`)},
				"mcp":      {Type: ServerTypeAggregate, TransportType: MCPClientTypeSSE, Discovery: &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second}},
			},
		}
		ResolveDefaults(cfg)

		mcp := cfg.MCPServers["mcp"]
		assert.Equal(t, []string{"postgres"}, mcp.Servers)
	})

	t.Run("does_not_override_explicit_empty_servers", func(t *testing.T) {
		cfg := &Config{
			MCPServers: map[string]*MCPClientConfig{
				"postgres": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				"mcp":      {Type: ServerTypeAggregate, TransportType: MCPClientTypeSSE, Servers: []string{}, Discovery: &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second}},
			},
		}
		ResolveDefaults(cfg)

		mcp := cfg.MCPServers["mcp"]
		assert.Equal(t, []string{}, mcp.Servers)
	})

	t.Run("excludes_aggregates_from_defaults", func(t *testing.T) {
		cfg := &Config{
			MCPServers: map[string]*MCPClientConfig{
				"postgres": {Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432"},
				"agg1":     {Type: ServerTypeAggregate, TransportType: MCPClientTypeSSE, Discovery: &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second}},
				"agg2":     {Type: ServerTypeAggregate, TransportType: MCPClientTypeSSE, Discovery: &DiscoveryConfig{Timeout: 10 * time.Second, CacheTTL: 60 * time.Second}},
			},
		}
		ResolveDefaults(cfg)

		assert.Equal(t, []string{"postgres"}, cfg.MCPServers["agg1"].Servers)
		assert.Equal(t, []string{"postgres"}, cfg.MCPServers["agg2"].Servers)
	})
}

func TestValidateConfig_ToolFilterMode(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError string
	}{
		{
			name: "valid_allow_mode",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"postgres": {
						Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432",
						Options: &Options{ToolFilter: &ToolFilterConfig{Mode: ToolFilterModeAllow, List: []string{"query"}}},
					},
				},
			},
		},
		{
			name: "valid_block_mode",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"postgres": {
						Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432",
						Options: &Options{ToolFilter: &ToolFilterConfig{Mode: ToolFilterModeBlock, List: []string{"drop"}}},
					},
				},
			},
		},
		{
			name: "invalid_mode",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"postgres": {
						Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432",
						Options: &Options{ToolFilter: &ToolFilterConfig{Mode: "allowlist", List: []string{"query"}}},
					},
				},
			},
			expectError: "invalid toolFilter mode 'allowlist'",
		},
		{
			name: "list_without_mode",
			config: &Config{
				Proxy: ProxyConfig{BaseURL: "https://test.example.com", Addr: ":8080"},
				MCPServers: map[string]*MCPClientConfig{
					"postgres": {
						Type: ServerTypeDirect, TransportType: MCPClientTypeSSE, URL: "http://localhost:5432",
						Options: &Options{ToolFilter: &ToolFilterConfig{List: []string{"query"}}},
					},
				},
			},
			expectError: "has toolFilter list but no mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractBasePath(t *testing.T) {
	tests := []struct {
		name         string
		baseURL      string
		expectedPath string
		expectError  bool
	}{
		{
			name:         "root_path",
			baseURL:      "http://localhost:8080",
			expectedPath: "/",
		},
		{
			name:         "simple_path",
			baseURL:      "http://localhost:8080/api",
			expectedPath: "/api",
		},
		{
			name:         "nested_path",
			baseURL:      "http://localhost:8080/api/v1",
			expectedPath: "/api/v1",
		},
		{
			name:         "trailing_slash_removed",
			baseURL:      "http://localhost:8080/api/",
			expectedPath: "/api",
		},
		{
			name:         "root_with_trailing_slash",
			baseURL:      "http://localhost:8080/",
			expectedPath: "/",
		},
		{
			name:         "path_with_multiple_segments",
			baseURL:      "https://mcp.company.com/mcp-api/v1",
			expectedPath: "/mcp-api/v1",
		},
		{
			name:        "invalid_url",
			baseURL:     "://invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Proxy: ProxyConfig{
					BaseURL: tt.baseURL,
				},
			}

			err := extractBasePath(&cfg)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPath, cfg.Proxy.BasePath)
			}
		})
	}
}
