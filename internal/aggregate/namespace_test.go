package aggregate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrefixToolName(t *testing.T) {
	assert.Equal(t, "postgres.query", PrefixToolName("postgres", "query", "."))
	assert.Equal(t, "linear.create_issue", PrefixToolName("linear", "create_issue", "."))
	assert.Equal(t, "postgres_query", PrefixToolName("postgres", "query", "_"))
	assert.Equal(t, "postgres-query", PrefixToolName("postgres", "query", "-"))
	assert.Equal(t, "postgres--query", PrefixToolName("postgres", "query", "--"))
	assert.Equal(t, "postgres._query", PrefixToolName("postgres", "query", "._"))
}

func TestParseToolName(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		delimiter  string
		wantServer string
		wantTool   string
		wantOK     bool
	}{
		{"dot_basic", "postgres.query", ".", "postgres", "query", true},
		{"dot_dotted_tool", "postgres.schema.list", ".", "postgres", "schema.list", true},
		{"dot_no_match", "query", ".", "", "", false},
		{"dot_empty", "", ".", "", "", false},
		{"underscore_basic", "postgres_query", "_", "postgres", "query", true},
		{"underscore_multi", "postgres_schema_list", "_", "postgres", "schema_list", true},
		{"hyphen_basic", "postgres-query", "-", "postgres", "query", true},
		{"hyphen_multi", "postgres-schema-list", "-", "postgres", "schema-list", true},
		{"multi_char_delimiter", "postgres--query", "--", "postgres", "query", true},
		{"multi_char_no_match", "postgres-query", "--", "", "", false},
		{"dot_underscore", "postgres._query", "._", "postgres", "query", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, tool, ok := ParseToolName(tt.input, tt.delimiter)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantServer, server)
			assert.Equal(t, tt.wantTool, tool)
		})
	}
}

func TestRoundTrip(t *testing.T) {
	delimiters := []string{".", "_", "-", "--", "._"}
	for _, delim := range delimiters {
		t.Run("delimiter_"+delim, func(t *testing.T) {
			prefixed := PrefixToolName("linear", "create_issue", delim)
			server, tool, ok := ParseToolName(prefixed, delim)
			assert.True(t, ok)
			assert.Equal(t, "linear", server)
			assert.Equal(t, "create_issue", tool)
		})
	}
}
