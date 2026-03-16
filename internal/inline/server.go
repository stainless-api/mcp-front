package inline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/log"
)

// Server implements an MCP server from inline configuration
type Server struct {
	name   string
	config Config
	tools  map[string]ResolvedToolConfig
}

// NewServer creates a new inline MCP server
func NewServer(name string, config Config, resolvedTools []ResolvedToolConfig) *Server {
	toolMap := make(map[string]ResolvedToolConfig)
	for _, tool := range resolvedTools {
		toolMap[tool.Name] = tool
	}

	return &Server{
		name:   name,
		config: config,
		tools:  toolMap,
	}
}

// Tool represents an MCP tool
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ServerCapabilities represents server capabilities
type ServerCapabilities struct {
	Tools map[string]Tool `json:"tools"`
}

// GetCapabilities returns the server capabilities
func (s *Server) GetCapabilities() ServerCapabilities {
	tools := make(map[string]Tool)

	for name, tool := range s.tools {
		var inputSchema map[string]any
		if len(tool.InputSchema) > 0 {
			if err := json.Unmarshal(tool.InputSchema, &inputSchema); err != nil {
				log.LogError("Failed to unmarshal input schema for tool %s: %v", name, err)
			}
		}

		tools[name] = Tool{
			Name:        name,
			Description: tool.Description,
			InputSchema: inputSchema,
		}
	}

	return ServerCapabilities{
		Tools: tools,
	}
}

// GetDescription returns the server description
func (s *Server) GetDescription() string {
	return s.config.Description
}

// HandleToolCall executes a tool and returns the result
func (s *Server) HandleToolCall(ctx context.Context, toolName string, args map[string]any) (any, error) {
	tool, exists := s.tools[toolName]
	if !exists {
		return nil, fmt.Errorf("tool %s not found", toolName)
	}

	// Set timeout if specified
	if tool.Timeout != "" {
		timeout, _ := time.ParseDuration(tool.Timeout)
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
	}

	if tool.HTMLFetch != nil {
		return s.executeHTMLFetch(ctx, tool, args)
	}

	if tool.HTTP != nil {
		return s.executeHTTP(ctx, tool, args)
	}

	cmd := exec.CommandContext(ctx, tool.Command, tool.Args...)

	// Set environment: parent first, then custom (so custom wins)
	cmd.Env = append(os.Environ(), func() []string {
		env := make([]string, 0, len(tool.Env))
		for k, v := range tool.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		return env
	}()...)

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Log execution
	log.LogDebug("Executing inline tool: %s %s", tool.Command, strings.Join(tool.Args, " "))

	// Execute
	err := cmd.Run()
	if err != nil {
		log.LogErrorWithFields("inline", "Tool execution failed", map[string]any{
			"tool":   toolName,
			"error":  err.Error(),
			"stderr": stderr.String(),
		})
		return map[string]any{
			"error":  err.Error(),
			"stderr": stderr.String(),
		}, fmt.Errorf("command failed: %w", err)
	}

	// Try to parse as JSON first
	var result any
	if err := json.Unmarshal(stdout.Bytes(), &result); err == nil {
		return result, nil
	}

	// Return as text if not JSON
	return map[string]any{
		"output": stdout.String(),
		"stderr": stderr.String(),
	}, nil
}

func (s *Server) executeHTTP(ctx context.Context, tool ResolvedToolConfig, args map[string]any) (any, error) {
	var req *http.Request
	var err error

	if strings.EqualFold(tool.HTTP.Method, "GET") {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, tool.HTTP.URL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		q := req.URL.Query()
		for k, v := range args {
			q.Set(k, fmt.Sprintf("%v", v))
		}
		req.URL.RawQuery = q.Encode()
	} else {
		body, err := json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal arguments: %w", err)
		}
		req, err = http.NewRequestWithContext(ctx, tool.HTTP.Method, tool.HTTP.URL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
	}

	for k, v := range tool.HTTP.Headers {
		req.Header.Set(k, v)
	}

	log.LogDebug("Executing inline HTTP tool: %s %s", tool.HTTP.Method, req.URL.String())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result any
	if err := json.Unmarshal(respBody, &result); err == nil {
		return result, nil
	}

	return map[string]any{"output": string(respBody)}, nil
}

func (s *Server) executeHTMLFetch(ctx context.Context, tool ResolvedToolConfig, args map[string]any) (any, error) {
	rawURL, ok := args[tool.HTMLFetch.URLArg].(string)
	if !ok || rawURL == "" {
		return nil, fmt.Errorf("missing required argument: %s", tool.HTMLFetch.URLArg)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if len(tool.HTMLFetch.AllowedDomains) > 0 {
		allowed := false
		for _, domain := range tool.HTMLFetch.AllowedDomains {
			if strings.EqualFold(parsed.Hostname(), domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("domain %q is not in the allowed list", parsed.Hostname())
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "Vori-MCP/1.0")

	log.LogDebug("Executing inline HTML fetch tool: GET %s", rawURL)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, rawURL)
	}

	body := io.LimitReader(resp.Body, 2*1024*1024)

	text, err := ExtractText(body, tool.HTMLFetch.Selector)
	if err != nil {
		return nil, fmt.Errorf("failed to extract content: %w", err)
	}

	return text, nil
}
