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
			wantRedirectURIs: []string{"https://example.com/callback"},
			wantScopes:       []string{"read", "write"},
			wantErr:          false,
		},
		{
			name:        "missing_redirect_uris",
			metadata:    map[string]any{},
			wantErr:     true,
			errContains: "no valid redirect URIs",
		},
		{
			name: "empty_redirect_uris",
			metadata: map[string]any{
				"redirect_uris": []any{},
			},
			wantErr:     true,
			errContains: "no valid redirect URIs",
		},
		{
			name: "redirect_uris_wrong_type",
			metadata: map[string]any{
				"redirect_uris": "https://example.com/callback",
			},
			wantErr:     true,
			errContains: "no valid redirect URIs",
		},
		{
			name: "redirect_uri_non_string_elements_ignored",
			metadata: map[string]any{
				"redirect_uris": []any{123, "https://example.com/callback", nil},
			},
			wantRedirectURIs: []string{"https://example.com/callback"},
			wantScopes:       []string{"read", "write"},
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectURIs, scopes, err := ParseClientRegistration(tt.metadata)

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
