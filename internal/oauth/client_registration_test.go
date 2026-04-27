package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClientRegistration(t *testing.T) {
	tests := []struct {
		name             string
		metadata         map[string]any
		allowedHosts     []string
		allowAny         bool
		wantRedirectURIs []string
		wantScopes       []string
		wantErr          bool
		errContains      string
	}{
		{
			name: "valid_with_single_redirect_uri",
			metadata: map[string]any{
				"redirect_uris": []any{"https://example.com/callback"},
			},
			allowAny:         true,
			wantRedirectURIs: []string{"https://example.com/callback"},
			wantScopes:       []string{"read", "write"},
			wantErr:          false,
		},
		{
			name: "valid_with_multiple_redirect_uris",
			metadata: map[string]any{
				"redirect_uris": []any{
					"https://example.com/callback",
					"https://example.com/callback2",
				},
			},
			allowAny: true,
			wantRedirectURIs: []string{
				"https://example.com/callback",
				"https://example.com/callback2",
			},
			wantScopes: []string{"read", "write"},
			wantErr:    false,
		},
		{
			name: "valid_with_custom_scopes",
			metadata: map[string]any{
				"redirect_uris": []any{"https://example.com/callback"},
				"scope":         "openid profile email",
			},
			allowAny:         true,
			wantRedirectURIs: []string{"https://example.com/callback"},
			wantScopes:       []string{"openid", "profile", "email"},
			wantErr:          false,
		},
		{
			name: "valid_with_empty_scope_uses_default",
			metadata: map[string]any{
				"redirect_uris": []any{"https://example.com/callback"},
				"scope":         "   ",
			},
			allowAny:         true,
			wantRedirectURIs: []string{"https://example.com/callback"},
			wantScopes:       []string{"read", "write"},
			wantErr:          false,
		},
		{
			name:        "missing_redirect_uris",
			metadata:    map[string]any{},
			allowAny:    true,
			wantErr:     true,
			errContains: "no valid redirect URIs",
		},
		{
			name: "empty_redirect_uris",
			metadata: map[string]any{
				"redirect_uris": []any{},
			},
			allowAny:    true,
			wantErr:     true,
			errContains: "no valid redirect URIs",
		},
		{
			name: "redirect_uris_wrong_type",
			metadata: map[string]any{
				"redirect_uris": "https://example.com/callback",
			},
			allowAny:    true,
			wantErr:     true,
			errContains: "no valid redirect URIs",
		},
		{
			name: "redirect_uri_non_string_elements_ignored",
			metadata: map[string]any{
				"redirect_uris": []any{123, "https://example.com/callback", nil},
			},
			allowAny:         true,
			wantRedirectURIs: []string{"https://example.com/callback"},
			wantScopes:       []string{"read", "write"},
			wantErr:          false,
		},

		// Policy enforcement: structural rejection (apply regardless of allowlist)
		{
			name: "rejects_javascript_scheme",
			metadata: map[string]any{
				"redirect_uris": []any{"javascript:alert(1)"},
			},
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "redirect_uri",
		},
		{
			name: "rejects_data_scheme",
			metadata: map[string]any{
				"redirect_uris": []any{"data:text/html,<script>alert(1)</script>"},
			},
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "redirect_uri",
		},
		{
			name: "rejects_uri_with_fragment",
			metadata: map[string]any{
				"redirect_uris": []any{"https://claude.ai/cb#stolen"},
			},
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "fragment",
		},
		{
			name: "rejects_relative_uri",
			metadata: map[string]any{
				"redirect_uris": []any{"/callback"},
			},
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "absolute",
		},
		// Policy enforcement: host allowlist
		{
			name: "rejects_host_not_in_allowlist",
			metadata: map[string]any{
				"redirect_uris": []any{"https://attacker.example/cb"},
			},
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "allowlist",
		},
		{
			name: "accepts_host_in_allowlist",
			metadata: map[string]any{
				"redirect_uris": []any{"https://claude.ai/api/mcp/auth_callback"},
			},
			allowedHosts:     []string{"https://claude.ai"},
			wantRedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"},
			wantScopes:       []string{"read", "write"},
			wantErr:          false,
		},
		{
			name: "rejects_when_one_of_many_uris_violates_policy",
			metadata: map[string]any{
				"redirect_uris": []any{
					"https://claude.ai/cb",
					"https://attacker.example/cb",
				},
			},
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "attacker.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectURIs, scopes, err := ParseClientRegistration(tt.metadata, tt.allowedHosts, tt.allowAny)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantRedirectURIs, redirectURIs)
			assert.Equal(t, tt.wantScopes, scopes)
		})
	}
}
