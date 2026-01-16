package oauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestExtractResourceParameters(t *testing.T) {
	tests := []struct {
		name     string
		rawQuery string
		want     []string
		wantErr  bool
	}{
		{
			name:     "single resource parameter",
			rawQuery: "resource=https://mcp.company.com/postgres",
			want:     []string{"https://mcp.company.com/postgres"},
		},
		{
			name:     "multiple resource parameters",
			rawQuery: "resource=https://mcp.company.com/postgres&resource=https://mcp.company.com/linear",
			want:     []string{"https://mcp.company.com/postgres", "https://mcp.company.com/linear"},
		},
		{
			name:     "duplicate parameters should deduplicate",
			rawQuery: "resource=https://mcp.company.com/postgres&resource=https://mcp.company.com/postgres",
			want:     []string{"https://mcp.company.com/postgres"},
		},
		{
			name:     "empty parameter should be skipped",
			rawQuery: "resource=&resource=https://mcp.company.com/postgres",
			want:     []string{"https://mcp.company.com/postgres"},
		},
		{
			name:     "no resource parameters",
			rawQuery: "client_id=test&state=abc",
			want:     []string{},
		},
		{
			name:     "empty query",
			rawQuery: "",
			want:     []string{},
		},
		{
			name: "exactly at limit (100 parameters)",
			rawQuery: func() string {
				params := make([]string, 100)
				for i := range 100 {
					params[i] = fmt.Sprintf("resource=https://example.com/service%d", i)
				}
				return strings.Join(params, "&")
			}(),
			want: func() []string {
				result := make([]string, 100)
				for i := range 100 {
					result[i] = fmt.Sprintf("https://example.com/service%d", i)
				}
				return result
			}(),
		},
		{
			name: "exceeds limit (101 parameters)",
			rawQuery: func() string {
				params := make([]string, 101)
				for i := range 101 {
					params[i] = fmt.Sprintf("resource=https://example.com/service%d", i)
				}
				return strings.Join(params, "&")
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{RawQuery: tt.rawQuery},
			}

			got, err := ExtractResourceParameters(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractResourceParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ExtractResourceParameters() = %v, want %v", got, tt.want)
				return
			}

			for i, resource := range got {
				if resource != tt.want[i] {
					t.Errorf("ExtractResourceParameters()[%d] = %v, want %v", i, resource, tt.want[i])
				}
			}
		})
	}
}

func TestValidateResourceURI(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		resourceURI string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid resource under root issuer",
			issuer:      "https://mcp.company.com",
			resourceURI: "https://mcp.company.com/postgres",
			wantErr:     false,
		},
		{
			name:        "valid nested path under root issuer",
			issuer:      "https://mcp.company.com",
			resourceURI: "https://mcp.company.com/api/v1/postgres",
			wantErr:     false,
		},
		{
			name:        "valid resource equals root issuer",
			issuer:      "https://mcp.company.com",
			resourceURI: "https://mcp.company.com",
			wantErr:     false,
		},
		{
			name:        "invalid relative URI",
			issuer:      "https://mcp.company.com",
			resourceURI: "/postgres",
			wantErr:     true,
			errContains: "must be absolute",
		},
		{
			name:        "invalid contains fragment",
			issuer:      "https://mcp.company.com",
			resourceURI: "https://mcp.company.com/postgres#section",
			wantErr:     true,
			errContains: "must not contain fragment",
		},
		{
			name:        "invalid scheme mismatch",
			issuer:      "https://mcp.company.com",
			resourceURI: "http://mcp.company.com/postgres",
			wantErr:     true,
			errContains: "scheme must match issuer",
		},
		{
			name:        "invalid host mismatch",
			issuer:      "https://mcp.company.com",
			resourceURI: "https://external.com/postgres",
			wantErr:     true,
			errContains: "host must match issuer",
		},
		{
			name:        "path normalization handled by url.Parse",
			issuer:      "https://mcp.company.com",
			resourceURI: "https://mcp.company.com/../postgres",
			wantErr:     false,
		},
		{
			name:        "invalid unsupported scheme",
			issuer:      "https://mcp.company.com",
			resourceURI: "ftp://mcp.company.com/postgres",
			wantErr:     true,
			errContains: "must be http or https",
		},
		{
			name:        "valid subpath for non-root issuer",
			issuer:      "https://mcp.company.com/api",
			resourceURI: "https://mcp.company.com/api/v1",
			wantErr:     false,
		},
		{
			name:        "invalid sibling path for non-root issuer",
			issuer:      "https://mcp.company.com/api",
			resourceURI: "https://mcp.company.com/apiv1",
			wantErr:     true,
			errContains: "not a valid subpath",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResourceURI(tt.resourceURI, tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateResourceURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateResourceURI() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestBuildResourceURI(t *testing.T) {
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
			want:        "https://mcp.company.com/postgres",
		},
		{
			name:        "issuer with path",
			issuer:      "https://mcp.company.com/mcp",
			serviceName: "postgres",
			want:        "https://mcp.company.com/mcp/postgres",
		},
		{
			name:        "issuer with trailing slash",
			issuer:      "https://mcp.company.com/",
			serviceName: "postgres",
			want:        "https://mcp.company.com/postgres",
		},
		{
			name:        "empty service name",
			issuer:      "https://mcp.company.com",
			serviceName: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildResourceURI(tt.issuer, tt.serviceName)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildResourceURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.want {
				t.Errorf("BuildResourceURI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateAudienceForService(t *testing.T) {
	issuer := "https://mcp.company.com"

	tests := []struct {
		name                 string
		requestPath          string
		tokenAudience        []string
		acceptIssuerAudience bool
		wantErr              bool
		errContains          string
	}{
		{
			name:                 "matching audience",
			requestPath:          "/postgres/sse",
			tokenAudience:        []string{"https://mcp.company.com/postgres"},
			acceptIssuerAudience: false,
			wantErr:              false,
		},
		{
			name:                 "matching audience with message endpoint",
			requestPath:          "/postgres/message",
			tokenAudience:        []string{"https://mcp.company.com/postgres"},
			acceptIssuerAudience: false,
			wantErr:              false,
		},
		{
			name:                 "matching audience in multi-audience token",
			requestPath:          "/postgres/sse",
			tokenAudience:        []string{"https://mcp.company.com/linear", "https://mcp.company.com/postgres"},
			acceptIssuerAudience: false,
			wantErr:              false,
		},
		{
			name:                 "wrong audience",
			requestPath:          "/postgres/sse",
			tokenAudience:        []string{"https://mcp.company.com/linear"},
			acceptIssuerAudience: false,
			wantErr:              true,
			errContains:          "does not include required resource",
		},
		{
			name:                 "empty audience",
			requestPath:          "/postgres/sse",
			tokenAudience:        []string{},
			acceptIssuerAudience: false,
			wantErr:              true,
			errContains:          "does not include required resource",
		},
		{
			name:                 "nil audience",
			requestPath:          "/postgres/sse",
			tokenAudience:        nil,
			acceptIssuerAudience: false,
			wantErr:              true,
			errContains:          "does not include required resource",
		},
		{
			name:                 "malformed request path",
			requestPath:          "/",
			tokenAudience:        []string{"https://mcp.company.com/postgres"},
			acceptIssuerAudience: false,
			wantErr:              true,
			errContains:          "does not contain service name",
		},
		{
			name:                 "empty request path",
			requestPath:          "",
			tokenAudience:        []string{"https://mcp.company.com/postgres"},
			acceptIssuerAudience: false,
			wantErr:              true,
			errContains:          "does not contain service name",
		},
		// Tests for acceptIssuerAudience workaround
		{
			name:                 "issuer audience accepted when enabled",
			requestPath:          "/postgres/sse",
			tokenAudience:        []string{"https://mcp.company.com"},
			acceptIssuerAudience: true,
			wantErr:              false,
		},
		{
			name:                 "issuer audience rejected when disabled",
			requestPath:          "/postgres/sse",
			tokenAudience:        []string{"https://mcp.company.com"},
			acceptIssuerAudience: false,
			wantErr:              true,
			errContains:          "does not include required resource",
		},
		{
			name:                 "per-service audience still works when issuer fallback enabled",
			requestPath:          "/postgres/sse",
			tokenAudience:        []string{"https://mcp.company.com/postgres"},
			acceptIssuerAudience: true,
			wantErr:              false,
		},
		{
			name:                 "issuer audience works for any service when enabled",
			requestPath:          "/linear/sse",
			tokenAudience:        []string{"https://mcp.company.com"},
			acceptIssuerAudience: true,
			wantErr:              false,
		},
		{
			name:                 "wrong issuer still rejected even when fallback enabled",
			requestPath:          "/postgres/sse",
			tokenAudience:        []string{"https://other.company.com"},
			acceptIssuerAudience: true,
			wantErr:              true,
			errContains:          "does not include required resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAudienceForService(tt.requestPath, tt.tokenAudience, issuer, tt.acceptIssuerAudience)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAudienceForService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateAudienceForService() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}
