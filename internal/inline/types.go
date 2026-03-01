package inline

import (
	"encoding/json"
)

// Config represents an inline MCP server configuration
type Config struct {
	Description string       `json:"description"`
	Tools       []ToolConfig `json:"tools"`
}

// ToolConfig represents a single tool in an inline MCP server.
// A tool uses either command execution (Command/Args/Env) or HTTP (HTTP), not both.
type ToolConfig struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	InputSchema json.RawMessage            `json:"inputSchema"`
	Command     string                     `json:"command"`           // Command to run (e.g., "docker", "gcloud", etc.)
	Args        []json.RawMessage          `json:"args,omitempty"`    // Arguments with {"$env": "..."} support
	Env         map[string]json.RawMessage `json:"env,omitempty"`     // Environment variables with {"$env": "..."} support
	HTTP        *HTTPConfig                `json:"http,omitempty"`    // HTTP request config (alternative to command execution)
	Timeout     string                     `json:"timeout,omitempty"` // Timeout for execution (e.g. "30s")
}

// HTTPConfig defines an HTTP request to make when a tool is called.
// Tool arguments are sent as the JSON request body.
type HTTPConfig struct {
	Method  string                     `json:"method"`
	URL     json.RawMessage            `json:"url"`               // Supports {"$env": "..."}
	Headers map[string]json.RawMessage `json:"headers,omitempty"` // Supports {"$env": "..."}
}

// ResolvedToolConfig represents a tool config with all values resolved
type ResolvedToolConfig struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	InputSchema json.RawMessage     `json:"inputSchema"`
	Command     string              `json:"command"`
	Args        []string            `json:"args,omitempty"`
	Env         map[string]string   `json:"env,omitempty"`
	HTTP        *ResolvedHTTPConfig `json:"http,omitempty"`
	Timeout     string              `json:"timeout,omitempty"`
}

// ResolvedHTTPConfig represents an HTTP config with all values resolved
type ResolvedHTTPConfig struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
}
