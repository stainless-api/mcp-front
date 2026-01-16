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

func TestServiceProtectedResourceMetadata(t *testing.T) {
	tests := []struct {
		name         string
		issuer       string
		serviceName  string
		wantResource string
		wantErr      bool
	}{
		{
			name:         "standard case",
			issuer:       "https://mcp.company.com",
			serviceName:  "postgres",
			wantResource: "https://mcp.company.com/postgres",
		},
		{
			name:         "issuer with base path",
			issuer:       "https://mcp.company.com/api",
			serviceName:  "postgres",
			wantResource: "https://mcp.company.com/api/postgres",
		},
		{
			name:         "issuer with trailing slash",
			issuer:       "https://mcp.company.com/",
			serviceName:  "linear",
			wantResource: "https://mcp.company.com/linear",
		},
		{
			name:         "different service",
			issuer:       "https://mcp.company.com",
			serviceName:  "gong",
			wantResource: "https://mcp.company.com/gong",
		},
		{
			name:        "invalid issuer",
			issuer:      "://invalid",
			serviceName: "postgres",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata, err := ServiceProtectedResourceMetadata(tt.issuer, tt.serviceName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ServiceProtectedResourceMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify resource field is service-specific
			resource := metadata["resource"].(string)
			if resource != tt.wantResource {
				t.Errorf("resource = %v, want %v", resource, tt.wantResource)
			}

			// Verify authorization_servers array contains issuer (not service-specific)
			authzServers, ok := metadata["authorization_servers"].([]string)
			if !ok || len(authzServers) == 0 {
				t.Error("authorization_servers is missing or empty")
			}

			// Authorization server should not be empty
			if authzServers[0] == "" {
				t.Error("authorization_servers[0] is empty")
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

func TestServiceProtectedResourceMetadataURI(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		serviceName string
		want        string
		wantErr     bool
	}{
		{
			name:        "standard case",
			issuer:      "https://mcp.company.com",
			serviceName: "postgres",
			want:        "https://mcp.company.com/.well-known/oauth-protected-resource/postgres",
		},
		{
			name:        "issuer with base path",
			issuer:      "https://mcp.company.com/mcp",
			serviceName: "linear",
			want:        "https://mcp.company.com/mcp/.well-known/oauth-protected-resource/linear",
		},
		{
			name:        "issuer with trailing slash",
			issuer:      "https://mcp.company.com/",
			serviceName: "gong",
			want:        "https://mcp.company.com/.well-known/oauth-protected-resource/gong",
		},
		{
			name:        "invalid issuer",
			issuer:      "://invalid",
			serviceName: "postgres",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ServiceProtectedResourceMetadataURI(tt.issuer, tt.serviceName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ServiceProtectedResourceMetadataURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if got != tt.want {
				t.Errorf("ServiceProtectedResourceMetadataURI() = %v, want %v", got, tt.want)
			}
		})
	}
}
