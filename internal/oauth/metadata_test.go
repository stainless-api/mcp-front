package oauth

import (
	"testing"
)

func TestAuthorizationServerMetadata(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{
			name:    "valid issuer",
			issuer:  "https://example.com",
			wantErr: false,
		},
		{
			name:    "issuer with path",
			issuer:  "https://example.com/oauth",
			wantErr: false,
		},
		{
			name:    "invalid issuer",
			issuer:  "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata, err := AuthorizationServerMetadata(tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizationServerMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify required fields are present
			if metadata["issuer"] != tt.issuer {
				t.Errorf("issuer = %v, want %v", metadata["issuer"], tt.issuer)
			}

			if metadata["authorization_endpoint"] == nil {
				t.Error("authorization_endpoint is nil")
			}

			if metadata["token_endpoint"] == nil {
				t.Error("token_endpoint is nil")
			}

			if metadata["registration_endpoint"] == nil {
				t.Error("registration_endpoint is nil")
			}

			// Verify response types
			responseTypes, ok := metadata["response_types_supported"].([]string)
			if !ok || len(responseTypes) == 0 {
				t.Error("response_types_supported is missing or empty")
			}

			// Verify grant types
			grantTypes, ok := metadata["grant_types_supported"].([]string)
			if !ok || len(grantTypes) == 0 {
				t.Error("grant_types_supported is missing or empty")
			}

			// Verify PKCE support
			codeChallenges, ok := metadata["code_challenge_methods_supported"].([]string)
			if !ok || len(codeChallenges) == 0 {
				t.Error("code_challenge_methods_supported is missing or empty")
			}

			// Verify resource indicators support
			resourceIndicators, ok := metadata["resource_indicators_supported"].(bool)
			if !ok || !resourceIndicators {
				t.Error("resource_indicators_supported should be true")
			}
		})
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{
			name:    "valid issuer",
			issuer:  "https://example.com",
			wantErr: false,
		},
		{
			name:    "issuer with path",
			issuer:  "https://example.com/oauth",
			wantErr: false,
		},
		{
			name:    "invalid issuer",
			issuer:  "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata, err := ProtectedResourceMetadata(tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProtectedResourceMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify resource field
			if metadata["resource"] != tt.issuer {
				t.Errorf("resource = %v, want %v", metadata["resource"], tt.issuer)
			}

			// Verify authorization_servers array
			authzServers, ok := metadata["authorization_servers"].([]string)
			if !ok || len(authzServers) == 0 {
				t.Error("authorization_servers is missing or empty")
			}

			if authzServers[0] != tt.issuer {
				t.Errorf("authorization_servers[0] = %v, want %v", authzServers[0], tt.issuer)
			}

			// Verify _links structure
			links, ok := metadata["_links"].(map[string]any)
			if !ok {
				t.Error("_links is missing or wrong type")
			}

			authzServerLink, ok := links["oauth-authorization-server"].(map[string]string)
			if !ok {
				t.Error("oauth-authorization-server link is missing or wrong type")
			}

			if authzServerLink["href"] == "" {
				t.Error("oauth-authorization-server href is empty")
			}
		})
	}
}
