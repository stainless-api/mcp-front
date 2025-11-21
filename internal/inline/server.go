package inline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	// Set up command with args as-is (already resolved by config parser)
	cmd := exec.CommandContext(ctx, tool.Command, tool.Args...)

	// Set environment variables
	for k, v := range tool.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	// Include parent environment
	cmd.Env = append(cmd.Env, os.Environ()...)

	// Set timeout if specified
	if tool.Timeout != "" {
		timeout, _ := time.ParseDuration(tool.Timeout)
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
			cmd = exec.CommandContext(ctx, tool.Command, tool.Args...)
		}
	}

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
