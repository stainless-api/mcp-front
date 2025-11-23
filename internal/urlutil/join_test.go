package urlutil

import (
	"testing"
)

func TestJoinPath(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		paths   []string
		want    string
		wantErr bool
	}{
		{
			name:  "simple join",
			base:  "https://example.com",
			paths: []string{"api", "v1"},
			want:  "https://example.com/api/v1",
		},
		{
			name:  "base with path",
			base:  "https://example.com/base",
			paths: []string{"api", "v1"},
			want:  "https://example.com/base/api/v1",
		},
		{
			name:  "trailing slash preserved",
			base:  "https://example.com",
			paths: []string{"api", "v1/"},
			want:  "https://example.com/api/v1/",
		},
		{
			name:  "well-known path",
			base:  "https://example.com",
			paths: []string{".well-known", "oauth-protected-resource"},
			want:  "https://example.com/.well-known/oauth-protected-resource",
		},
		{
			name:  "empty paths",
			base:  "https://example.com",
			paths: []string{},
			want:  "https://example.com",
		},
		{
			name:  "base with trailing slash",
			base:  "https://example.com/",
			paths: []string{"api"},
			want:  "https://example.com/api",
		},
		{
			name:    "invalid base URL",
			base:    "://invalid",
			paths:   []string{"api"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JoinPath(tt.base, tt.paths...)
			if (err != nil) != tt.wantErr {
				t.Errorf("JoinPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("JoinPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMustJoinPath(t *testing.T) {
	// Test normal operation
	result := MustJoinPath("https://example.com", "api", "v1")
	if result != "https://example.com/api/v1" {
		t.Errorf("MustJoinPath() = %v, want %v", result, "https://example.com/api/v1")
	}

	// Test panic on invalid URL
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustJoinPath() should have panicked")
		}
	}()
	MustJoinPath("://invalid", "api")
}
