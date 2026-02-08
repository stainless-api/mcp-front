package hostmatch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		patterns []string
		want     bool
	}{
		{"exact match", "api.example.com", []string{"api.example.com"}, true},
		{"no match", "api.example.com", []string{"other.com"}, false},
		{"wildcard match", "api.example.com", []string{"*.example.com"}, true},
		{"wildcard no match on bare domain", "example.com", []string{"*.example.com"}, false},
		{"wildcard deep subdomain", "deep.api.example.com", []string{"*.example.com"}, true},
		{"case insensitive", "API.Example.COM", []string{"api.example.com"}, true},
		{"strip port", "api.example.com:443", []string{"api.example.com"}, true},
		{"strip port from pattern", "api.example.com", []string{"api.example.com:443"}, true},
		{"empty patterns", "api.example.com", nil, false},
		{"empty host", "", []string{"api.example.com"}, false},
		{"multiple patterns", "api.example.com", []string{"other.com", "*.example.com"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Match(tt.host, tt.patterns))
		})
	}
}
