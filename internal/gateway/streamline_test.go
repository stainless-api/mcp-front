package gateway

import (
	"encoding/json"
	"testing"
)

func TestStreamlineDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short description unchanged",
			input:    "Execute a SQL query",
			expected: "Execute a SQL query",
		},
		{
			name:     "strips examples block",
			input:    "Search for issues.\n\n<examples>\n### Find bugs\nsearch_issues(query='bugs')\n</examples>\n\nReturns results.",
			expected: "Search for issues.\n\nReturns results.",
		},
		{
			name:     "strips hints block",
			input:    "Get issue details.\n\n<hints>\n- Use issueUrl parameter\n- Extract from URL\n</hints>",
			expected: "Get issue details.",
		},
		{
			name:     "strips multiple blocks",
			input:    "Tool description.\n\n<examples>\nfoo\n</examples>\n\nMiddle text.\n\n<hints>\nbar\n</hints>",
			expected: "Tool description.\n\nMiddle text.",
		},
		{
			name:  "truncates long description at sentence boundary",
			input: "This is a tool that does many things. It supports complex queries with boolean operators. It also handles pagination and filtering. " + "Additional details that push it well beyond the maximum allowed description length for streamlined responses in the gateway multiplexer endpoint. More text here to ensure truncation happens correctly at a sentence boundary.",
			expected: "This is a tool that does many things. It supports complex queries with boolean operators. It also handles pagination and filtering. Additional details that push it well beyond the maximum allowed description length for streamlined responses in the gateway multiplexer endpoint.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := streamlineDescription(tt.input)
			if got != tt.expected {
				t.Errorf("streamlineDescription():\ngot:  %q\nwant: %q", got, tt.expected)
			}
		})
	}
}

func TestStreamlineInputSchema(t *testing.T) {
	t.Run("strips property descriptions", func(t *testing.T) {
		input := json.RawMessage(`{
			"type": "object",
			"properties": {
				"query": {
					"type": "string",
					"description": "The SQL query to execute against the database"
				},
				"limit": {
					"type": "integer",
					"default": 50,
					"description": "Maximum number of rows to return"
				}
			},
			"required": ["query"]
		}`)

		result := streamlineInputSchema(input)

		var parsed map[string]any
		if err := json.Unmarshal(result, &parsed); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}

		props := parsed["properties"].(map[string]any)

		queryProp := props["query"].(map[string]any)
		if _, hasDesc := queryProp["description"]; hasDesc {
			t.Error("query property should not have description")
		}
		if queryProp["type"] != "string" {
			t.Error("query type should be preserved")
		}

		limitProp := props["limit"].(map[string]any)
		if _, hasDesc := limitProp["description"]; hasDesc {
			t.Error("limit property should not have description")
		}
		if limitProp["default"] != float64(50) {
			t.Error("limit default should be preserved")
		}

		required := parsed["required"].([]any)
		if len(required) != 1 || required[0] != "query" {
			t.Error("required should be preserved")
		}
	})

	t.Run("simplifies anyOf nullable types", func(t *testing.T) {
		input := json.RawMessage(`{
			"type": "object",
			"properties": {
				"region": {
					"anyOf": [
						{"type": "string", "description": "The region URL"},
						{"type": "null"}
					],
					"default": null,
					"description": "Optional region parameter"
				}
			}
		}`)

		result := streamlineInputSchema(input)

		var parsed map[string]any
		if err := json.Unmarshal(result, &parsed); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}

		props := parsed["properties"].(map[string]any)
		regionProp := props["region"].(map[string]any)

		if _, hasAnyOf := regionProp["anyOf"]; hasAnyOf {
			t.Error("anyOf should be simplified away")
		}
		if regionProp["type"] != "string" {
			t.Errorf("type should be string, got %v", regionProp["type"])
		}
		if _, hasDesc := regionProp["description"]; hasDesc {
			t.Error("description should be stripped")
		}
	})

	t.Run("handles nested objects", func(t *testing.T) {
		input := json.RawMessage(`{
			"type": "object",
			"properties": {
				"telemetry": {
					"type": "object",
					"properties": {
						"intent": {
							"type": "string",
							"description": "Briefly describe the wider context task"
						}
					},
					"required": ["intent"]
				}
			}
		}`)

		result := streamlineInputSchema(input)

		var parsed map[string]any
		if err := json.Unmarshal(result, &parsed); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}

		props := parsed["properties"].(map[string]any)
		telemetry := props["telemetry"].(map[string]any)
		innerProps := telemetry["properties"].(map[string]any)
		intent := innerProps["intent"].(map[string]any)

		if _, hasDesc := intent["description"]; hasDesc {
			t.Error("nested property description should be stripped")
		}
	})

	t.Run("preserves enum values", func(t *testing.T) {
		input := json.RawMessage(`{
			"type": "object",
			"properties": {
				"status": {
					"type": "string",
					"enum": ["resolved", "unresolved", "ignored"],
					"description": "The new status for the issue"
				}
			}
		}`)

		result := streamlineInputSchema(input)

		var parsed map[string]any
		if err := json.Unmarshal(result, &parsed); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}

		props := parsed["properties"].(map[string]any)
		status := props["status"].(map[string]any)

		enumVals := status["enum"].([]any)
		if len(enumVals) != 3 {
			t.Errorf("enum should have 3 values, got %d", len(enumVals))
		}
	})

	t.Run("returns input unchanged on invalid JSON", func(t *testing.T) {
		input := json.RawMessage(`not valid json`)
		result := streamlineInputSchema(input)
		if string(result) != string(input) {
			t.Error("invalid JSON should be returned unchanged")
		}
	})

	t.Run("returns empty input unchanged", func(t *testing.T) {
		result := streamlineInputSchema(nil)
		if result != nil {
			t.Error("nil input should return nil")
		}
	})

	t.Run("strips validation constraints and extensions", func(t *testing.T) {
		input := json.RawMessage(`{
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"limit": {
					"type": "number",
					"minimum": 1,
					"maximum": 100,
					"default": 10
				},
				"query": {
					"type": "string",
					"minLength": 2,
					"maxLength": 200,
					"pattern": "^[a-z]+$",
					"format": "uri"
				},
				"output": {
					"type": "string",
					"enum": ["TABLE", "WIDE", "YAML"],
					"x-google-enum-descriptions": ["Table format", "Wide format", "YAML format"]
				}
			}
		}`)

		result := streamlineInputSchema(input)

		var parsed map[string]any
		if err := json.Unmarshal(result, &parsed); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}

		if _, has := parsed["additionalProperties"]; has {
			t.Error("top-level additionalProperties should be stripped")
		}

		props := parsed["properties"].(map[string]any)

		limit := props["limit"].(map[string]any)
		if _, has := limit["minimum"]; has {
			t.Error("minimum should be stripped")
		}
		if _, has := limit["maximum"]; has {
			t.Error("maximum should be stripped")
		}
		if limit["default"] != float64(10) {
			t.Error("default should be preserved")
		}

		query := props["query"].(map[string]any)
		for _, field := range []string{"minLength", "maxLength", "pattern", "format"} {
			if _, has := query[field]; has {
				t.Errorf("%s should be stripped", field)
			}
		}

		output := props["output"].(map[string]any)
		if _, has := output["x-google-enum-descriptions"]; has {
			t.Error("x-google-* fields should be stripped")
		}
		enumVals := output["enum"].([]any)
		if len(enumVals) != 3 {
			t.Error("enum values should be preserved")
		}
	})
}
