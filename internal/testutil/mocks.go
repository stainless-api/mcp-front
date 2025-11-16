package testutil

import (
	"context"

	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/mock"
)

type MockMCPClient struct {
	mock.Mock
}

func (m *MockMCPClient) Initialize(ctx context.Context, request mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.InitializeResult), args.Error(1)
}

func (m *MockMCPClient) ListTools(ctx context.Context, request mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ListToolsResult), args.Error(1)
}

func (m *MockMCPClient) CallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.CallToolResult), args.Error(1)
}

func (m *MockMCPClient) ListPrompts(ctx context.Context, request mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ListPromptsResult), args.Error(1)
}

func (m *MockMCPClient) GetPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.GetPromptResult), args.Error(1)
}

func (m *MockMCPClient) ListResources(ctx context.Context, request mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ListResourcesResult), args.Error(1)
}

func (m *MockMCPClient) ReadResource(ctx context.Context, request mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ReadResourceResult), args.Error(1)
}

func (m *MockMCPClient) ListResourceTemplates(ctx context.Context, request mcp.ListResourceTemplatesRequest) (*mcp.ListResourceTemplatesResult, error) {
	args := m.Called(ctx, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mcp.ListResourceTemplatesResult), args.Error(1)
}

func (m *MockMCPClient) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMCPClient) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMCPClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockMCPServer struct {
	mock.Mock
}

func (m *MockMCPServer) AddTool(tool mcp.Tool, handler server.ToolHandlerFunc) {
	m.Called(tool, handler)
}

func (m *MockMCPServer) AddPrompt(prompt mcp.Prompt, handler server.PromptHandlerFunc) {
	m.Called(prompt, handler)
}

func (m *MockMCPServer) AddResource(resource mcp.Resource, handler server.ResourceHandlerFunc) {
	m.Called(resource, handler)
}

func (m *MockMCPServer) AddResourceTemplate(template mcp.ResourceTemplate, handler server.ResourceHandlerFunc) {
	m.Called(template, handler)
}

type MockSession struct {
	mock.Mock
}

func (m *MockSession) Initialize() {
	m.Called()
}

func (m *MockSession) Initialized() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockSession) NotificationChannel() chan<- mcp.JSONRPCNotification {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(chan<- mcp.JSONRPCNotification)
}

func (m *MockSession) SessionID() string {
	args := m.Called()
	return args.String(0)
}

type MockSessionWithTools struct {
	MockSession
}

func (m *MockSessionWithTools) GetSessionTools() map[string]server.ServerTool {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(map[string]server.ServerTool)
}

func (m *MockSessionWithTools) SetSessionTools(tools map[string]server.ServerTool) {
	m.Called(tools)
}

type MockUserTokenStore struct {
	mock.Mock
}

func (m *MockUserTokenStore) GetUserToken(ctx context.Context, userEmail, serverName string) (*storage.StoredToken, error) {
	args := m.Called(ctx, userEmail, serverName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.StoredToken), args.Error(1)
}

func (m *MockUserTokenStore) SetUserToken(ctx context.Context, userEmail, serverName string, token *storage.StoredToken) error {
	args := m.Called(ctx, userEmail, serverName, token)
	return args.Error(0)
}

func (m *MockUserTokenStore) DeleteUserToken(ctx context.Context, userEmail, serverName string) error {
	args := m.Called(ctx, userEmail, serverName)
	return args.Error(0)
}

func (m *MockUserTokenStore) ListUserServices(ctx context.Context, userEmail string) ([]string, error) {
	args := m.Called(ctx, userEmail)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// MockEncryptor is a mock implementation of crypto.Encryptor
type MockEncryptor struct {
	mock.Mock
}

func (m *MockEncryptor) Encrypt(plaintext string) (string, error) {
	args := m.Called(plaintext)
	return args.String(0), args.Error(1)
}

func (m *MockEncryptor) Decrypt(ciphertext string) (string, error) {
	args := m.Called(ciphertext)
	return args.String(0), args.Error(1)
}
