package inline

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
)

// ResolveConfig resolves environment variables in inline config
func ResolveConfig(rawConfig json.RawMessage) (Config, []ResolvedToolConfig, error) {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return Config{}, nil, fmt.Errorf("failed to unmarshal inline config: %w", err)
	}

	resolvedTools := make([]ResolvedToolConfig, len(cfg.Tools))

	for i, tool := range cfg.Tools {
		resolved := ResolvedToolConfig{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
			Command:     tool.Command,
			Timeout:     tool.Timeout,
			Args:        make([]string, 0, len(tool.Args)),
			Env:         make(map[string]string),
		}

		// Resolve args using the config package's parser
		if len(tool.Args) > 0 {
			values, needsToken, err := config.ParseConfigValueSlice(tool.Args)
			if err != nil {
				return Config{}, nil, fmt.Errorf("failed to resolve args for tool %s: %w", tool.Name, err)
			}
			// Check if any args need user tokens (not supported for inline)
			for j, needs := range needsToken {
				if needs {
					return Config{}, nil, fmt.Errorf("user token references not supported in inline tools (arg %d of tool %s)", j, tool.Name)
				}
			}
			resolved.Args = values
		}

		// Resolve env using the config package's parser
		if len(tool.Env) > 0 {
			values, needsToken, err := config.ParseConfigValueMap(tool.Env)
			if err != nil {
				return Config{}, nil, fmt.Errorf("failed to resolve env for tool %s: %w", tool.Name, err)
			}
			// Check if any env vars need user tokens (not supported for inline)
			for k, needs := range needsToken {
				if needs {
					return Config{}, nil, fmt.Errorf("user token references not supported in inline tools (env %s of tool %s)", k, tool.Name)
				}
			}
			resolved.Env = values
		}

		if tool.HTTP != nil {
			resolvedHTTP := &ResolvedHTTPConfig{
				Method:  tool.HTTP.Method,
				Headers: make(map[string]string),
			}

			urlValues, urlNeedsToken, err := config.ParseConfigValueSlice([]json.RawMessage{tool.HTTP.URL})
			if err != nil {
				return Config{}, nil, fmt.Errorf("failed to resolve HTTP URL for tool %s: %w", tool.Name, err)
			}
			if urlNeedsToken[0] {
				return Config{}, nil, fmt.Errorf("user token references not supported in inline tools (HTTP URL of tool %s)", tool.Name)
			}
			resolvedHTTP.URL = urlValues[0]

			if len(tool.HTTP.Headers) > 0 {
				headerValues, headerNeedsToken, err := config.ParseConfigValueMap(tool.HTTP.Headers)
				if err != nil {
					return Config{}, nil, fmt.Errorf("failed to resolve HTTP headers for tool %s: %w", tool.Name, err)
				}
				for k, needs := range headerNeedsToken {
					if needs {
						return Config{}, nil, fmt.Errorf("user token references not supported in inline tools (HTTP header %s of tool %s)", k, tool.Name)
					}
				}
				resolvedHTTP.Headers = headerValues
			}

			resolved.HTTP = resolvedHTTP
		}

		if tool.HTMLFetch != nil {
			resolved.HTMLFetch = tool.HTMLFetch
		}

		// Validate timeout format if specified
		if resolved.Timeout != "" {
			if _, err := time.ParseDuration(resolved.Timeout); err != nil {
				return Config{}, nil, fmt.Errorf("invalid timeout format for tool %s: %w (use Go duration format like '30s', '5m', '1h')", tool.Name, err)
			}
		}

		resolvedTools[i] = resolved
	}

	return cfg, resolvedTools, nil
}
