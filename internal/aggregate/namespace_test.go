package aggregate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrefixToolName(t *testing.T) {
	assert.Equal(t, "postgres.query", PrefixToolName("postgres", "query"))
	assert.Equal(t, "linear.create_issue", PrefixToolName("linear", "create_issue"))
}

func TestParseToolName(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantServer string
		wantTool   string
		wantOK     bool
	}{
		{"basic", "postgres.query", "postgres", "query", true},
		{"dotted_tool", "postgres.schema.list", "postgres", "schema.list", true},
		{"no_dot", "query", "", "", false},
		{"empty", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, tool, ok := ParseToolName(tt.input)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantServer, server)
			assert.Equal(t, tt.wantTool, tool)
		})
	}
}

func TestRoundTrip(t *testing.T) {
	prefixed := PrefixToolName("linear", "create_issue")
	server, tool, ok := ParseToolName(prefixed)
	assert.True(t, ok)
	assert.Equal(t, "linear", server)
	assert.Equal(t, "create_issue", tool)
}
