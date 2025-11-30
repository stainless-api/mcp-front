package idp

import (
	"testing"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name         string
		cfg          config.IDPConfig
		wantType     string
		wantErr      bool
		errContains  string
		skipCreation bool
	}{
		{
			name: "google_provider",
			cfg: config.IDPConfig{
				Provider:     "google",
				ClientID:     "test-client-id",
				ClientSecret: config.Secret("test-client-secret"),
				RedirectURI:  "https://example.com/callback",
			},
			wantType: "google",
			wantErr:  false,
		},
		{
			name: "github_provider",
			cfg: config.IDPConfig{
				Provider:     "github",
				ClientID:     "test-client-id",
				ClientSecret: config.Secret("test-client-secret"),
				RedirectURI:  "https://example.com/callback",
			},
			wantType: "github",
			wantErr:  false,
		},
		{
			name: "azure_provider_missing_tenant",
			cfg: config.IDPConfig{
				Provider:     "azure",
				ClientID:     "test-client-id",
				ClientSecret: config.Secret("test-client-secret"),
				RedirectURI:  "https://example.com/callback",
			},
			wantErr:     true,
			errContains: "tenantId is required",
		},
		{
			name: "oidc_provider_missing_endpoints",
			cfg: config.IDPConfig{
				Provider:     "oidc",
				ClientID:     "test-client-id",
				ClientSecret: config.Secret("test-client-secret"),
				RedirectURI:  "https://example.com/callback",
			},
			wantErr:     true,
			errContains: "discoveryUrl or all endpoints",
		},
		{
			name: "oidc_provider_with_direct_endpoints",
			cfg: config.IDPConfig{
				Provider:         "oidc",
				ClientID:         "test-client-id",
				ClientSecret:     config.Secret("test-client-secret"),
				RedirectURI:      "https://example.com/callback",
				AuthorizationURL: "https://idp.example.com/authorize",
				TokenURL:         "https://idp.example.com/token",
				UserInfoURL:      "https://idp.example.com/userinfo",
			},
			wantType: "oidc",
			wantErr:  false,
		},
		{
			name: "unknown_provider",
			cfg: config.IDPConfig{
				Provider: "unknown",
			},
			wantErr:     true,
			errContains: "unknown provider type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.cfg)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, provider)
			assert.Equal(t, tt.wantType, provider.Type())
		})
	}
}
