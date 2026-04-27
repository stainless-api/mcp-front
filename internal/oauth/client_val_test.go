package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRequestedRedirectURI(t *testing.T) {
	client := &testClient{
		id:           "test-client",
		redirectURIs: []string{"https://claude.ai/cb"},
	}

	tests := []struct {
		name         string
		redirectURI  string
		allowedHosts []string
		allowAny     bool
		wantErr      bool
		errContains  string
	}{
		{
			name:         "accepts registered URI within policy",
			redirectURI:  "https://claude.ai/cb",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      false,
		},
		{
			name:        "rejects empty URI",
			redirectURI: "",
			allowAny:    true,
			wantErr:     true,
			errContains: "required",
		},
		{
			name:        "rejects URI not in registered set",
			redirectURI: "https://attacker.example/steal",
			allowAny:    true,
			wantErr:     true,
			errContains: "not registered",
		},
		{
			name:         "rejects URI registered but off-allowlist (defense in depth)",
			redirectURI:  "https://claude.ai/cb",
			allowedHosts: []string{"https://other.example"},
			wantErr:      true,
			errContains:  "allowlist",
		},
		{
			name:         "rejects javascript even when registered",
			redirectURI:  "javascript:alert(1)",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
		},
	}

	// Stretch: also register javascript: so "registered" check passes and we
	// confirm the policy still rejects it.
	clientWithJS := &testClient{
		id:           "test-client",
		redirectURIs: []string{"https://claude.ai/cb", "javascript:alert(1)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := client
			if tt.redirectURI == "javascript:alert(1)" {
				c = clientWithJS
			}
			err := ValidateRequestedRedirectURI(tt.redirectURI, c, tt.allowedHosts, tt.allowAny)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateRedirectURIPolicy(t *testing.T) {
	tests := []struct {
		name         string
		uri          string
		allowedHosts []string
		allowAny     bool
		wantErr      bool
		errContains  string
	}{
		// Structural checks (apply regardless of allowAny)
		{
			name:         "rejects javascript scheme",
			uri:          "javascript:alert(1)",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "scheme",
		},
		{
			name:         "rejects data scheme",
			uri:          "data:text/html,<script>alert(1)</script>",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "scheme",
		},
		{
			name:         "rejects file scheme",
			uri:          "file:///etc/passwd",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
		},
		{
			name:         "rejects relative URI",
			uri:          "/callback",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "absolute",
		},
		{
			name:         "rejects URI with fragment",
			uri:          "https://claude.ai/cb#token=stolen",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "fragment",
		},
		{
			name:         "rejects empty URI",
			uri:          "",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
		},
		{
			name:         "rejects URI without host",
			uri:          "https://",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "host",
		},
		// Structural checks still apply when allowAny=true
		{
			name:        "rejects javascript scheme even with allowAny",
			uri:         "javascript:alert(1)",
			allowAny:    true,
			wantErr:     true,
			errContains: "scheme",
		},
		{
			name:        "rejects fragment even with allowAny",
			uri:         "https://anything.example/cb#x",
			allowAny:    true,
			wantErr:     true,
			errContains: "fragment",
		},
		{
			name:     "allowAny accepts arbitrary https host",
			uri:      "https://attacker.example/cb",
			allowAny: true,
			wantErr:  false,
		},
		// Host allowlist checks
		{
			name:         "accepts host on allowlist",
			uri:          "https://claude.ai/cb",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      false,
		},
		{
			name:         "accepts host on allowlist with path",
			uri:          "https://claude.ai/api/mcp/auth_callback",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      false,
		},
		{
			name:         "rejects host not on allowlist",
			uri:          "https://attacker.example/cb",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "not allowed",
		},
		{
			name:         "rejects scheme not on allowlist",
			uri:          "http://claude.ai/cb",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      true,
			errContains:  "not allowed",
		},
		// Port handling
		{
			name:         "port-less allowlist entry accepts any port on that host",
			uri:          "https://claude.ai:8443/cb",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      false,
		},
		{
			name:         "port-less allowlist entry accepts default port",
			uri:          "https://claude.ai:443/cb",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      false,
		},
		{
			name:         "explicit port allowlist entry rejects different port",
			uri:          "https://claude.ai:8080/cb",
			allowedHosts: []string{"https://claude.ai:443"},
			wantErr:      true,
			errContains:  "not allowed",
		},
		{
			name:         "explicit port allowlist entry accepts matching port",
			uri:          "https://claude.ai:8080/cb",
			allowedHosts: []string{"https://claude.ai:8080"},
			wantErr:      false,
		},
		{
			name:         "loopback IP allowlist accepts arbitrary port",
			uri:          "http://127.0.0.1:53219/cb",
			allowedHosts: []string{"http://127.0.0.1"},
			wantErr:      false,
		},
		// Multiple allowlist entries
		{
			name:         "matches second entry in allowlist",
			uri:          "https://claude.ai/cb",
			allowedHosts: []string{"https://other.example", "https://claude.ai"},
			wantErr:      false,
		},
		// Case-insensitive scheme + host (RFC 3986 §3.2.2)
		{
			name:         "case-insensitive host match",
			uri:          "https://CLAUDE.AI/cb",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      false,
		},
		{
			name:         "case-insensitive scheme match",
			uri:          "HTTPS://claude.ai/cb",
			allowedHosts: []string{"https://claude.ai"},
			wantErr:      false,
		},
		{
			name:         "uppercase entry matches lowercase URI",
			uri:          "https://claude.ai/cb",
			allowedHosts: []string{"HTTPS://CLAUDE.AI"},
			wantErr:      false,
		},
		// Empty allowlist with allowAny=false rejects everything
		{
			name:         "empty allowlist without allowAny rejects everything",
			uri:          "https://claude.ai/cb",
			allowedHosts: nil,
			allowAny:     false,
			wantErr:      true,
			errContains:  "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURIPolicy(tt.uri, tt.allowedHosts, tt.allowAny)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}
