package client

import (
	"context"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestStdioSession_DiscoverAndRegisterCapabilities(t *testing.T) {
	ctx := context.Background()

	t.Run("session with tools support", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		stdioSession := &StdioSession{
			client: client,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ServerInfo:      mcp.Implementation{Name: "test-server", Version: "1.0"},
			}, nil)

		tools := []mcp.Tool{
			{Name: "tool1", Description: "Test tool 1"},
			{Name: "tool2", Description: "Test tool 2"},
		}
		listToolsResult := &mcp.ListToolsResult{}
		listToolsResult.Tools = tools
		mockClient.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
			Return(listToolsResult, nil).Once()

		mockSession.On("SessionID").Return("test-session-123").Times(4)

		mockSession.On("SetSessionTools", mock.MatchedBy(func(tools map[string]server.ServerTool) bool {
			return len(tools) == 2 &&
				tools["tool1"].Tool.Name == "tool1" &&
				tools["tool2"].Tool.Name == "tool2"
		})).Return()

		mockClient.On("ListPrompts", ctx, mock.AnythingOfType("mcp.ListPromptsRequest")).
			Return(&mcp.ListPromptsResult{}, nil)
		mockClient.On("ListResources", ctx, mock.AnythingOfType("mcp.ListResourcesRequest")).
			Return(&mcp.ListResourcesResult{}, nil)
		mockClient.On("ListResourceTemplates", ctx, mock.AnythingOfType("mcp.ListResourceTemplatesRequest")).
			Return(&mcp.ListResourceTemplatesResult{}, nil)

		err := stdioSession.DiscoverAndRegisterCapabilities(
			ctx,
			mockServer,
			"user@example.com",
			false,
			mockTokenStore,
			"test-server",
			"http://localhost",
			nil,
			mockSession,
		)

		require.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockSession.AssertExpectations(t)
	})

	t.Run("session without tools support", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSession)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		stdioSession := &StdioSession{
			client: client,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ServerInfo:      mcp.Implementation{Name: "test-server", Version: "1.0"},
			}, nil)

		mockSession.On("SessionID").Return("test-session-123")

		err := stdioSession.DiscoverAndRegisterCapabilities(
			ctx,
			mockServer,
			"user@example.com",
			false,
			mockTokenStore,
			"test-server",
			"http://localhost",
			nil,
			mockSession,
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "session does not support session-specific tools")
		mockClient.AssertExpectations(t)
	})

	t.Run("tool filtering with session", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
			options: &config.Options{
				ToolFilter: &config.ToolFilterConfig{
					Mode: config.ToolFilterModeAllow,
					List: []string{"tool1"},
				},
			},
		}

		stdioSession := &StdioSession{
			client: client,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ServerInfo:      mcp.Implementation{Name: "test-server", Version: "1.0"},
			}, nil)

		tools := []mcp.Tool{
			{Name: "tool1", Description: "Test tool 1"},
			{Name: "tool2", Description: "Test tool 2"},
		}
		listToolsResult := &mcp.ListToolsResult{}
		listToolsResult.Tools = tools
		mockClient.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
			Return(listToolsResult, nil).Once()

		mockSession.On("SessionID").Return("test-session-456").Times(4)

		mockSession.On("SetSessionTools", mock.MatchedBy(func(tools map[string]server.ServerTool) bool {
			return len(tools) == 1 && tools["tool1"].Tool.Name == "tool1"
		})).Return()

		mockClient.On("ListPrompts", ctx, mock.AnythingOfType("mcp.ListPromptsRequest")).
			Return(&mcp.ListPromptsResult{}, nil)
		mockClient.On("ListResources", ctx, mock.AnythingOfType("mcp.ListResourcesRequest")).
			Return(&mcp.ListResourcesResult{}, nil)
		mockClient.On("ListResourceTemplates", ctx, mock.AnythingOfType("mcp.ListResourceTemplatesRequest")).
			Return(&mcp.ListResourceTemplatesResult{}, nil)

		err := stdioSession.DiscoverAndRegisterCapabilities(
			ctx,
			mockServer,
			"user@example.com",
			false,
			mockTokenStore,
			"test-server",
			"http://localhost",
			nil,
			mockSession,
		)

		require.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockSession.AssertExpectations(t)
	})

	t.Run("initialization failure", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		stdioSession := &StdioSession{
			client: client,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(nil, errors.New("initialization failed"))

		err := stdioSession.DiscoverAndRegisterCapabilities(
			ctx,
			mockServer,
			"user@example.com",
			false,
			mockTokenStore,
			"test-server",
			"http://localhost",
			nil,
			mockSession,
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "initialization failed")
		mockClient.AssertExpectations(t)
	})

	t.Run("tool listing failure", func(t *testing.T) {
		mockClient := new(testutil.MockMCPClient)
		mockServer := server.NewMCPServer("test", "1.0")
		mockSession := new(testutil.MockSessionWithTools)
		mockTokenStore := new(testutil.MockUserTokenStore)

		client := &Client{
			name:            "test-client",
			needManualStart: false,
			client:          mockClient,
		}

		stdioSession := &StdioSession{
			client: client,
		}

		mockClient.On("Initialize", ctx, mock.AnythingOfType("mcp.InitializeRequest")).
			Return(&mcp.InitializeResult{}, nil)

		mockClient.On("ListTools", ctx, mock.AnythingOfType("mcp.ListToolsRequest")).
			Return(nil, errors.New("failed to list tools"))

		mockSession.On("SessionID").Return("test-session")

		err := stdioSession.DiscoverAndRegisterCapabilities(
			ctx,
			mockServer,
			"user@example.com",
			false,
			mockTokenStore,
			"test-server",
			"http://localhost",
			nil,
			mockSession,
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list tools")
		mockClient.AssertExpectations(t)
	})
}
