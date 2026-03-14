package gateway

import (
	"encoding/json"
	"regexp"
	"strings"
)

const maxDescriptionLength = 300

var (
	xmlBlockPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?s)<examples>.*?</examples>`),
		regexp.MustCompile(`(?s)<hints>.*?</hints>`),
		regexp.MustCompile(`(?s)<example>.*?</example>`),
	}
	multipleNewlines = regexp.MustCompile(`\n{3,}`)
)

func streamlineDescription(desc string) string {
	for _, pat := range xmlBlockPatterns {
		desc = pat.ReplaceAllString(desc, "")
	}
	desc = multipleNewlines.ReplaceAllString(desc, "\n\n")
	desc = strings.TrimSpace(desc)
	if len(desc) > maxDescriptionLength {
		desc = desc[:maxDescriptionLength]
		if i := strings.LastIndex(desc, ". "); i > maxDescriptionLength/2 {
			desc = desc[:i+1]
		}
	}
	return desc
}

func streamlineInputSchema(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}

	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return raw
	}

	stripSchemaClutter(schema)
	simplifyNullableTypes(schema)

	result, err := json.Marshal(schema)
	if err != nil {
		return raw
	}
	return result
}

// Fields that are only used for validation, not for understanding tool usage.
var validationOnlyFields = []string{
	"description",
	"additionalProperties",
	"minimum",
	"maximum",
	"minLength",
	"maxLength",
	"pattern",
	"format",
}

func stripSchemaClutter(schema map[string]any) {
	delete(schema, "additionalProperties")

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return
	}

	for _, prop := range props {
		propMap, ok := prop.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range validationOnlyFields {
			delete(propMap, field)
		}

		// Strip x-google-* extension fields
		for k := range propMap {
			if strings.HasPrefix(k, "x-") {
				delete(propMap, k)
			}
		}

		// Recurse into nested objects
		stripSchemaClutter(propMap)

		// Handle items for arrays
		if items, ok := propMap["items"].(map[string]any); ok {
			for _, field := range validationOnlyFields {
				delete(items, field)
			}
			stripSchemaClutter(items)
		}
	}
}

func simplifyNullableTypes(schema map[string]any) {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return
	}

	for key, prop := range props {
		propMap, ok := prop.(map[string]any)
		if !ok {
			continue
		}

		anyOf, ok := propMap["anyOf"].([]any)
		if !ok || len(anyOf) != 2 {
			continue
		}

		// Find the non-null type in anyOf
		var realType map[string]any
		hasNull := false
		for _, item := range anyOf {
			itemMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if itemMap["type"] == "null" {
				hasNull = true
			} else {
				realType = itemMap
			}
		}

		if hasNull && realType != nil {
			simplified := make(map[string]any)
			for k, v := range realType {
				if k != "description" {
					simplified[k] = v
				}
			}
			if def, ok := propMap["default"]; ok {
				simplified["default"] = def
			}
			props[key] = simplified
		}
	}
}
