package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// MCPClientInterface is the interface we need from mcp-go client
type MCPClientInterface interface {
	Initialize(ctx context.Context, request mcp.InitializeRequest) (*mcp.InitializeResult, error)
	ListTools(ctx context.Context, request mcp.ListToolsRequest) (*mcp.ListToolsResult, error)
	CallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
	ListPrompts(ctx context.Context, request mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error)
	GetPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error)
	ListResources(ctx context.Context, request mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error)
	ReadResource(ctx context.Context, request mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error)
	ListResourceTemplates(ctx context.Context, request mcp.ListResourceTemplatesRequest) (*mcp.ListResourceTemplatesResult, error)
	Ping(ctx context.Context) error
	Start(ctx context.Context) error
	Close() error
}

// TransportCreator creates the underlying MCP transport client
type TransportCreator func(conf *config.MCPClientConfig) (MCPClientInterface, error)

// Client represents an MCP client wrapper
type Client struct {
	name            string
	needPing        bool
	needManualStart bool
	client          MCPClientInterface
	options         *config.Options
}

// NewMCPClient creates a new MCP client using the default transport creator
func NewMCPClient(name string, conf *config.MCPClientConfig) (*Client, error) {
	return NewMCPClientWith(name, conf, DefaultTransportCreator)
}

// NewMCPClientWith creates a new MCP client with a custom transport creator
func NewMCPClientWith(name string, conf *config.MCPClientConfig, createTransport TransportCreator) (*Client, error) {
	transport, err := createTransport(conf)
	if err != nil {
		return nil, fmt.Errorf("creating transport: %w", err)
	}

	// Determine if we need ping/manual start based on transport type
	needPing := conf.URL != ""
	needManualStart := conf.URL != ""

	return &Client{
		name:            name,
		needPing:        needPing,
		needManualStart: needManualStart,
		client:          transport,
		options:         conf.Options,
	}, nil
}

// DefaultTransportCreator creates the appropriate MCP transport based on config
func DefaultTransportCreator(conf *config.MCPClientConfig) (MCPClientInterface, error) {
	if conf.Command != "" || conf.TransportType == config.MCPClientTypeStdio {
		if conf.Command == "" {
			return nil, errors.New("command is required for stdio transport")
		}

		envs := make([]string, 0, len(conf.Env))
		for k, v := range conf.Env {
			envs = append(envs, fmt.Sprintf("%s=%s", k, v))
		}

		log.LogInfoWithFields("client", "Starting stdio MCP process", map[string]any{
			"command": conf.Command,
			"args":    conf.Args,
			"env":     envs,
		})

		mcpClient, err := client.NewStdioMCPClient(conf.Command, envs, conf.Args...)
		if err != nil {
			log.LogErrorWithFields("client", "Failed to start stdio MCP process", map[string]any{
				"command": conf.Command,
				"args":    conf.Args,
				"error":   err.Error(),
			})
			return nil, err
		}

		log.LogInfoWithFields("client", "Successfully started stdio MCP process", map[string]any{
			"command": conf.Command,
		})

		return mcpClient, nil
	}

	if conf.URL != "" {
		if conf.TransportType == config.MCPClientTypeStreamable {
			var options []transport.StreamableHTTPCOption
			if len(conf.Headers) > 0 {
				options = append(options, transport.WithHTTPHeaders(conf.Headers))
			}
			if conf.Timeout > 0 {
				options = append(options, transport.WithHTTPTimeout(conf.Timeout))
			}
			mcpClient, err := client.NewStreamableHttpClient(conf.URL, options...)
			if err != nil {
				return nil, err
			}
			return mcpClient, nil
		} else {
			var options []transport.ClientOption
			if len(conf.Headers) > 0 {
				options = append(options, client.WithHeaders(conf.Headers))
			}
			mcpClient, err := client.NewSSEMCPClient(conf.URL, options...)
			if err != nil {
				return nil, err
			}
			return mcpClient, nil
		}
	}

	return nil, errors.New("invalid client type: must have either command or url")
}

// startPingTask runs a goroutine that pings the MCP server every 30 seconds.
// The goroutine lifecycle is tied to the provided context:
// - For stdio clients: context is cancelled when the request ends, stopping pings
// - For SSE/HTTP clients: context lives as long as the connection, which is correct
// This ensures no goroutine leaks as the ping task stops when the connection closes.
func (c *Client) startPingTask(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
PingLoop:
	for {
		select {
		case <-ctx.Done():
			log.Logf("<%s> Context done, stopping ping", c.name)
			break PingLoop
		case <-ticker.C:
			_ = c.client.Ping(ctx)
		}
	}
}

func (c *Client) addToolsToServer(
	ctx context.Context,
	mcpServer *server.MCPServer,
	userEmail string,
	requiresToken bool,
	tokenStore storage.UserTokenStore,
	serverName string,
	setupBaseURL string,
	userAuth *config.UserAuthentication,
	session server.ClientSession,
) error {
	toolsRequest := mcp.ListToolsRequest{}
	filterFunc := func(toolName string) bool {
		return true
	}

	if c.options != nil && c.options.ToolFilter != nil && len(c.options.ToolFilter.List) > 0 {
		filterSet := make(map[string]struct{})
		mode := config.ToolFilterMode(strings.ToLower(string(c.options.ToolFilter.Mode)))
		for _, toolName := range c.options.ToolFilter.List {
			filterSet[toolName] = struct{}{}
		}
		switch mode {
		case config.ToolFilterModeAllow:
			filterFunc = func(toolName string) bool {
				_, inList := filterSet[toolName]
				if !inList {
					log.Logf("<%s> Ignoring tool %s as it is not in allow list", c.name, toolName)
				}
				return inList
			}
		case config.ToolFilterModeBlock:
			filterFunc = func(toolName string) bool {
				_, inList := filterSet[toolName]
				if inList {
					log.Logf("<%s> Ignoring tool %s as it is in block list", c.name, toolName)
				}
				return !inList
			}
		default:
			log.Logf("<%s> Unknown tool filter mode: %s, skipping tool filter", c.name, mode)
		}
	}

	log.LogInfoWithFields("client", "Starting tool discovery", map[string]any{
		"server": c.name,
	})

	totalTools := 0

	var sessionWithTools server.SessionWithTools
	var sessionTools map[string]server.ServerTool
	if session != nil {
		var ok bool
		sessionWithTools, ok = session.(server.SessionWithTools)
		if !ok {
			return fmt.Errorf("session does not support session-specific tools")
		}
		sessionTools = make(map[string]server.ServerTool)
		log.LogInfoWithFields("client", "Using session-specific tool registration", map[string]any{
			"server":    c.name,
			"sessionID": session.SessionID(),
		})
	}

	for {
		tools, err := c.client.ListTools(ctx, toolsRequest)
		if err != nil {
			log.LogErrorWithFields("client", "Failed to list tools", map[string]any{
				"server": c.name,
				"error":  err.Error(),
			})
			return err
		}
		if len(tools.Tools) == 0 {
			break
		}
		log.Logf("<%s> Successfully listed %d tools", c.name, len(tools.Tools))
		totalTools += len(tools.Tools)

		for _, tool := range tools.Tools {
			if filterFunc(tool.Name) {
				log.LogDebugWithFields("client", "Adding tool", map[string]any{
					"server":      c.name,
					"tool":        tool.Name,
					"description": tool.Description,
				})
				// Wrap the tool handler to check for user tokens if required
				var handler server.ToolHandlerFunc
				if requiresToken && tokenStore != nil {
					handler = c.wrapToolHandler(
						c.client.CallTool,
						requiresToken,
						tokenStore,
						userEmail,
						serverName,
						setupBaseURL,
						userAuth,
					)
				} else {
					handler = c.client.CallTool
				}

				if sessionTools != nil {
					sessionTools[tool.Name] = server.ServerTool{
						Tool:    tool,
						Handler: handler,
					}
				} else {
					mcpServer.AddTool(tool, handler)
				}
			}
		}
		if tools.NextCursor == "" {
			break
		}
		toolsRequest.Params.Cursor = tools.NextCursor
	}

	if len(sessionTools) > 0 {
		sessionWithTools.SetSessionTools(sessionTools)
		log.LogInfoWithFields("client", "Registered session-specific tools", map[string]any{
			"server":    c.name,
			"sessionID": session.SessionID(),
			"toolCount": len(sessionTools),
		})
	}

	log.LogInfoWithFields("client", "Tool discovery completed", map[string]any{
		"server":     c.name,
		"totalTools": totalTools,
	})

	return nil
}

func (c *Client) addPromptsToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	log.LogInfoWithFields("client", "Starting prompt discovery", map[string]any{
		"server": c.name,
	})

	totalPrompts := 0
	promptsRequest := mcp.ListPromptsRequest{}
	for {
		prompts, err := c.client.ListPrompts(ctx, promptsRequest)
		if err != nil {
			log.LogErrorWithFields("client", "Failed to list prompts", map[string]any{
				"server": c.name,
				"error":  err.Error(),
			})
			return err
		}
		if len(prompts.Prompts) == 0 {
			break
		}
		log.Logf("<%s> Successfully listed %d prompts", c.name, len(prompts.Prompts))
		totalPrompts += len(prompts.Prompts)
		for _, prompt := range prompts.Prompts {
			log.Logf("<%s> Adding prompt %s", c.name, prompt.Name)
			mcpServer.AddPrompt(prompt, c.client.GetPrompt)
		}
		if prompts.NextCursor == "" {
			break
		}
		promptsRequest.Params.Cursor = prompts.NextCursor
	}

	log.LogInfoWithFields("client", "Prompt discovery completed", map[string]any{
		"server":       c.name,
		"totalPrompts": totalPrompts,
	})

	return nil
}

func (c *Client) addResourcesToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	log.LogInfoWithFields("client", "Starting resource discovery", map[string]any{
		"server": c.name,
	})

	totalResources := 0
	resourcesRequest := mcp.ListResourcesRequest{}
	for {
		resources, err := c.client.ListResources(ctx, resourcesRequest)
		if err != nil {
			log.LogErrorWithFields("client", "Failed to list resources", map[string]any{
				"server": c.name,
				"error":  err.Error(),
			})
			return err
		}
		if len(resources.Resources) == 0 {
			break
		}
		log.Logf("<%s> Successfully listed %d resources", c.name, len(resources.Resources))
		totalResources += len(resources.Resources)
		for _, resource := range resources.Resources {
			log.Logf("<%s> Adding resource %s", c.name, resource.Name)
			mcpServer.AddResource(resource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				readResource, e := c.client.ReadResource(ctx, request)
				if e != nil {
					return nil, e
				}
				return readResource.Contents, nil
			})
		}
		if resources.NextCursor == "" {
			break
		}
		resourcesRequest.Params.Cursor = resources.NextCursor

	}

	log.LogInfoWithFields("client", "Resource discovery completed", map[string]any{
		"server":         c.name,
		"totalResources": totalResources,
	})

	return nil
}

func (c *Client) addResourceTemplatesToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	resourceTemplatesRequest := mcp.ListResourceTemplatesRequest{}
	for {
		resourceTemplates, err := c.client.ListResourceTemplates(ctx, resourceTemplatesRequest)
		if err != nil {
			return err
		}
		if len(resourceTemplates.ResourceTemplates) == 0 {
			break
		}
		log.Logf("<%s> Successfully listed %d resource templates", c.name, len(resourceTemplates.ResourceTemplates))
		for _, resourceTemplate := range resourceTemplates.ResourceTemplates {
			log.Logf("<%s> Adding resource template %s", c.name, resourceTemplate.Name)
			mcpServer.AddResourceTemplate(resourceTemplate, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				readResource, e := c.client.ReadResource(ctx, request)
				if e != nil {
					return nil, e
				}
				return readResource.Contents, nil
			})
		}
		if resourceTemplates.NextCursor == "" {
			break
		}
		resourceTemplatesRequest.Params.Cursor = resourceTemplates.NextCursor
	}
	return nil
}

// wrapToolHandler wraps a tool handler to check for user tokens when required
func (c *Client) wrapToolHandler(
	originalHandler func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error),
	requiresToken bool,
	tokenStore storage.UserTokenStore,
	userEmail string,
	serverName string,
	setupBaseURL string,
	userAuth *config.UserAuthentication,
) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(toolCtx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Log tool invocation
		log.LogInfoWithFields("client", "Tool invocation requested", map[string]any{
			"server": serverName,
			"tool":   request.Params.Name,
			"user":   userEmail,
		})

		// If token is required, check if we have it
		if requiresToken && tokenStore != nil {
			if userEmail == "" {
				// This shouldn't happen with proper config validation
				// (requiresUserToken requires OAuth to be configured)
				log.LogErrorWithFields("client", "User token required but no user email provided", map[string]any{
					"service": serverName,
					"tool":    request.Params.Name,
				})

				errorData := createTokenRequiredError(
					serverName,
					setupBaseURL,
					"configuration error: this service requires user tokens but OAuth is not properly configured.",
				)

				errorJSON, _ := json.Marshal(errorData)
				return mcp.NewToolResultError(string(errorJSON)), nil
			}

			_, err := tokenStore.GetUserToken(toolCtx, userEmail, serverName)
			if err != nil {
				// Token not found - return structured error
				tokenSetupURL := fmt.Sprintf("%s/my/tokens", setupBaseURL)

				var errorMessage string
				if userAuth != nil {
					errorMessage = fmt.Sprintf(
						"token required: %s requires a user token to access the API. "+
							"please visit %s to set up your %s token. %s",
						userAuth.DisplayName,
						tokenSetupURL,
						userAuth.DisplayName,
						userAuth.Instructions,
					)
				} else {
					errorMessage = fmt.Sprintf(
						"token required: this service requires a user token. "+
							"please visit %s to configure your token.",
						tokenSetupURL,
					)
				}

				errorData := createTokenRequiredError(
					serverName,
					setupBaseURL,
					errorMessage,
				)

				errorJSON, _ := json.Marshal(errorData)
				return mcp.NewToolResultError(string(errorJSON)), nil
			}
		}

		// Token check passed or not required, call original handler
		result, err := originalHandler(toolCtx, request)

		if err != nil {
			log.LogErrorWithFields("client", "Tool invocation failed", map[string]any{
				"server": serverName,
				"tool":   request.Params.Name,
				"user":   userEmail,
				"error":  err.Error(),
			})
		} else {
			log.LogInfoWithFields("client", "Tool invocation completed", map[string]any{
				"server": serverName,
				"tool":   request.Params.Name,
				"user":   userEmail,
			})
		}

		return result, err
	}
}

// Close closes the MCP client
func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// createTokenRequiredError creates the structured error for missing user tokens
func createTokenRequiredError(serverName, setupBaseURL string, message string) map[string]any {
	tokenSetupURL := fmt.Sprintf("%s/my/tokens", setupBaseURL)

	return map[string]any{
		"jsonrpc": "2.0",
		"error": map[string]any{
			"code":    "token_required",
			"message": message,
			"data": map[string]any{
				"service":       serverName,
				"tokenSetupUrl": tokenSetupURL,
				"instructions": map[string]any{
					"ai": "CRITICAL: You MUST pass these error details EXACTLY as provided to the human. " +
						"You are FORBIDDEN from modifying URLs or instructions. " +
						"Tell the human they need to visit the tokenSetupUrl to configure their token.",
					"human": message,
				},
			},
		},
	}
}
