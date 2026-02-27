package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespaceTool(t *testing.T) {
	assert.Equal(t, "linear__create_issue", NamespaceTool("linear", "create_issue"))
	assert.Equal(t, "postgres__query_db", NamespaceTool("postgres", "query_db"))
}

func TestParseNamespacedTool(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantService string
		wantTool    string
		wantErr     bool
	}{
		{"valid", "linear__create_issue", "linear", "create_issue", false},
		{"tool with underscore", "postgres__query_db", "postgres", "query_db", false},
		{"tool with double underscore", "svc__tool__extra", "svc", "tool__extra", false},
		{"no separator", "create_issue", "", "", true},
		{"empty service", "__create_issue", "", "", true},
		{"empty tool", "linear__", "", "", true},
		{"just separator", "__", "", "", true},
		{"empty string", "", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, tool, err := ParseNamespacedTool(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantService, svc)
				assert.Equal(t, tt.wantTool, tool)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	namespaced := NamespaceTool("linear", "create_issue")
	svc, tool, err := ParseNamespacedTool(namespaced)
	require.NoError(t, err)
	assert.Equal(t, "linear", svc)
	assert.Equal(t, "create_issue", tool)
}
