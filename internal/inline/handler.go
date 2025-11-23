package inline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgellow/mcp-front/internal/crypto"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/jsonrpc"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/sse"
)

// MCPServer defines the interface that Handler depends on
type MCPServer interface {
	GetCapabilities() ServerCapabilities
	HandleToolCall(ctx context.Context, toolName string, args map[string]any) (any, error)
	GetDescription() string
}

// Handler implements the MCP protocol for inline servers
type Handler struct {
	server MCPServer
	name   string
}

// NewHandler creates a new inline MCP handler
func NewHandler(name string, server MCPServer) *Handler {
	return &Handler{
		server: server,
		name:   name,
	}
}

// ServeHTTP handles HTTP requests for the inline MCP server
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/sse", "/" + h.name + "/sse":
		h.handleSSE(w, r)
	case "/message", "/" + h.name + "/message":
		h.handleMessage(w, r)
	default:
		jsonwriter.WriteNotFound(w, "Endpoint not found")
	}
}

// handleSSE handles SSE connections
func (h *Handler) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Set up SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonwriter.WriteInternalServerError(w, "Streaming unsupported")
		return
	}

	// Generate a cryptographically secure session ID
	sessionID := crypto.GenerateSecureToken()

	// Send initial endpoint message
	endpoint := map[string]any{
		"type":        "endpoint",
		"name":        h.name,
		"version":     "1.0",
		"description": h.server.GetDescription(),
	}

	if err := sse.WriteMessage(w, flusher, endpoint); err != nil {
		log.LogError("Failed to write endpoint message: %v", err)
		return
	}

	// Send message endpoint path for MCP protocol
	// MCP clients expect to receive the message endpoint after the endpoint message
	// Send as relative path - client will construct full URL based on where it connected
	messageEndpointPath := fmt.Sprintf("/%s/message?sessionId=%s", h.name, sessionID)
	if err := sse.WriteMessage(w, flusher, messageEndpointPath); err != nil {
		log.LogError("Failed to write message endpoint path: %v", err)
		return
	}

	// Start the SSE loop
	h.runSSELoop(r.Context(), w, flusher)
}

// runSSELoop runs the SSE keep-alive loop
func (h *Handler) runSSELoop(ctx context.Context, w http.ResponseWriter, flusher http.Flusher) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sse.WriteMessage(w, flusher, map[string]any{
				"type": "ping",
			}); err != nil {
				return
			}
		}
	}
}

// handleMessage handles JSON-RPC messages
func (h *Handler) handleMessage(w http.ResponseWriter, r *http.Request) {
	// For inline servers, we accept any sessionId parameter without validation
	// since inline servers are stateless and don't track sessions
	_ = r.URL.Query().Get("sessionId") // Accept but don't validate

	var request jsonrpc.Request

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		// Invalid JSON should return HTTP 400
		jsonrpc.WriteInvalidJSON(w)
		return
	}

	switch request.Method {
	case "initialize":
		h.handleInitialize(w, &request)
	case "tools/list":
		h.handleToolsList(w, &request)
	case "tools/call":
		h.handleToolCall(w, &request)
	default:
		jsonrpc.WriteError(w, request.ID, jsonrpc.MethodNotFound, "Method not found")
	}
}

// handleInitialize handles the initialize request
func (h *Handler) handleInitialize(w http.ResponseWriter, req *jsonrpc.Request) {
	result := map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    h.server.GetCapabilities(),
		"serverInfo": map[string]any{
			"name":    h.name,
			"version": "1.0",
		},
	}

	if err := jsonrpc.WriteResult(w, req.ID, result); err != nil {
		log.LogError("Failed to write initialize response: %v", err)
	}
}

// handleToolsList handles the tools/list request
func (h *Handler) handleToolsList(w http.ResponseWriter, req *jsonrpc.Request) {
	capabilities := h.server.GetCapabilities()

	tools := make([]map[string]any, 0, len(capabilities.Tools))
	for _, tool := range capabilities.Tools {
		tools = append(tools, map[string]any{
			"name":        tool.Name,
			"description": tool.Description,
			"inputSchema": tool.InputSchema,
		})
	}

	result := map[string]any{
		"tools": tools,
	}

	if err := jsonrpc.WriteResult(w, req.ID, result); err != nil {
		log.LogError("Failed to write tools/list response: %v", err)
	}
}

// handleToolCall handles tool execution requests
func (h *Handler) handleToolCall(w http.ResponseWriter, req *jsonrpc.Request) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		jsonrpc.WriteError(w, req.ID, jsonrpc.InvalidParams, "Invalid parameters")
		return
	}

	// Execute the tool
	result, err := h.server.HandleToolCall(context.Background(), params.Name, params.Arguments)
	if err != nil {
		jsonrpc.WriteError(w, req.ID, jsonrpc.InternalError, err.Error())
		return
	}

	response := map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": formatToolResult(result),
			},
		},
		"isError": err != nil,
	}

	if err := jsonrpc.WriteResult(w, req.ID, response); err != nil {
		log.LogError("Failed to write tools/call response: %v", err)
	}
}

// formatToolResult formats the tool result for display
func formatToolResult(result any) string {
	// If it's already a string, return it
	if str, ok := result.(string); ok {
		return str
	}

	// If it's a map with output field, return that
	if m, ok := result.(map[string]any); ok {
		if output, exists := m["output"]; exists {
			if str, ok := output.(string); ok {
				return str
			}
		}
	}

	// Otherwise, marshal as JSON
	bytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", result)
	}
	return string(bytes)
}
