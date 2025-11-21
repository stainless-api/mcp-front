package emailutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase email",
			input:    "user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "uppercase email",
			input:    "USER@EXAMPLE.COM",
			expected: "user@example.com",
		},
		{
			name:     "mixed case email",
			input:    "User@Example.Com",
			expected: "user@example.com",
		},
		{
			name:     "email with leading whitespace",
			input:    "  user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "email with trailing whitespace",
			input:    "user@example.com  ",
			expected: "user@example.com",
		},
		{
			name:     "email with surrounding whitespace",
			input:    "  User@Example.Com  ",
			expected: "user@example.com",
		},
		{
			name:     "email with tabs and newlines",
			input:    "\t\nUser@Example.Com\n\t",
			expected: "user@example.com",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only whitespace",
			input:    "   \t\n   ",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Normalize(tt.input)
			assert.Equal(t, tt.expected, result, "Normalize(%q)", tt.input)
		})
	}
}
