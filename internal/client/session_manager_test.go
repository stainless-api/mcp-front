package client

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/testutil"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStdioSessionManager_CreateAndRetrieve(t *testing.T) {
	mockCreator := func(name string, config *config.MCPClientConfig) (*Client, error) {
		mockClient := new(testutil.MockMCPClient)
		mockClient.On("Close").Return(nil).Maybe()
		return &Client{client: mockClient}, nil
	}

	sm := NewStdioSessionManager(
		WithClientCreator(mockCreator),
		WithTimeout(1*time.Minute),
	)
	defer sm.Shutdown()

	key := SessionKey{
		UserEmail:  "test@example.com",
		ServerName: "test-server",
		SessionID:  "session-123",
	}

	config := &config.MCPClientConfig{
		Command: "echo",
		Args:    []string{"test"},
	}

	info := mcp.Implementation{
		Name:    "test",
		Version: "1.0",
	}

	// Create session
	session1, err := sm.GetOrCreateSession(context.Background(), key, config, info, "http://localhost", "")
	require.NoError(t, err)
	require.NotNil(t, session1)

	// Retrieve same session
	session2, err := sm.GetOrCreateSession(context.Background(), key, config, info, "http://localhost", "")
	require.NoError(t, err)
	require.NotNil(t, session2)

	// Should be the same instance
	assert.Equal(t, session1, session2)

	// Direct retrieval
	session3, ok := sm.GetSession(key)
	assert.True(t, ok)
	assert.Equal(t, session1, session3)
}

func TestStdioSessionManager_UserLimits(t *testing.T) {
	mockCreator := func(name string, config *config.MCPClientConfig) (*Client, error) {
		mockClient := new(testutil.MockMCPClient)
		mockClient.On("Close").Return(nil).Maybe()
		return &Client{client: mockClient}, nil
	}

	sm := NewStdioSessionManager(
		WithClientCreator(mockCreator),
		WithMaxPerUser(2),
	)
	defer sm.Shutdown()

	userEmail := "test@example.com"
	config := &config.MCPClientConfig{Command: "echo"}
	info := mcp.Implementation{Name: "test", Version: "1.0"}

	// Create first session
	key1 := SessionKey{UserEmail: userEmail, ServerName: "server", SessionID: "1"}
	_, err := sm.GetOrCreateSession(context.Background(), key1, config, info, "http://localhost", "")
	require.NoError(t, err)

	// Create second session (at limit)
	key2 := SessionKey{UserEmail: userEmail, ServerName: "server", SessionID: "2"}
	_, err = sm.GetOrCreateSession(context.Background(), key2, config, info, "http://localhost", "")
	require.NoError(t, err)

	// Try to create third session (should fail)
	key3 := SessionKey{UserEmail: userEmail, ServerName: "server", SessionID: "3"}
	_, err = sm.GetOrCreateSession(context.Background(), key3, config, info, "http://localhost", "")
	assert.ErrorIs(t, err, ErrUserLimitExceeded)

	// Different user should work
	key4 := SessionKey{UserEmail: "other@example.com", ServerName: "server", SessionID: "4"}
	_, err = sm.GetOrCreateSession(context.Background(), key4, config, info, "http://localhost", "")
	require.NoError(t, err)
}

func TestStdioSessionManager_RemoveSession(t *testing.T) {
	var createdClient *testutil.MockMCPClient
	mockCreator := func(name string, config *config.MCPClientConfig) (*Client, error) {
		mockClient := new(testutil.MockMCPClient)
		mockClient.On("Close").Return(nil).Once()
		createdClient = mockClient
		return &Client{client: mockClient}, nil
	}

	sm := NewStdioSessionManager(WithClientCreator(mockCreator))
	defer sm.Shutdown()

	key := SessionKey{
		UserEmail:  "test@example.com",
		ServerName: "test-server",
		SessionID:  "session-123",
	}

	config := &config.MCPClientConfig{Command: "echo"}
	info := mcp.Implementation{Name: "test", Version: "1.0"}

	// Create session
	session, err := sm.GetOrCreateSession(context.Background(), key, config, info, "http://localhost", "")
	require.NoError(t, err)
	require.NotNil(t, session)

	// Remove session
	sm.RemoveSession(key)

	// Session should not exist
	_, ok := sm.GetSession(key)
	assert.False(t, ok)

	// Client should have been closed
	createdClient.AssertExpectations(t)
}

func TestStdioSessionManager_Timeout(t *testing.T) {
	mockCreator := func(name string, config *config.MCPClientConfig) (*Client, error) {
		mockClient := new(testutil.MockMCPClient)
		mockClient.On("Close").Return(nil).Maybe()
		return &Client{client: mockClient}, nil
	}

	sm := NewStdioSessionManager(
		WithClientCreator(mockCreator),
		WithTimeout(100*time.Millisecond),
		WithCleanupInterval(50*time.Millisecond),
	)
	defer sm.Shutdown()

	key := SessionKey{
		UserEmail:  "test@example.com",
		ServerName: "test-server",
		SessionID:  "session-123",
	}

	config := &config.MCPClientConfig{Command: "echo"}
	info := mcp.Implementation{Name: "test", Version: "1.0"}

	// Create session
	session, err := sm.GetOrCreateSession(context.Background(), key, config, info, "http://localhost", "")
	require.NoError(t, err)
	require.NotNil(t, session)

	// Session should exist initially
	_, ok := sm.GetSession(key)
	assert.True(t, ok)

	// Wait for timeout and cleanup
	time.Sleep(200 * time.Millisecond)

	// Session should be gone
	_, ok = sm.GetSession(key)
	assert.False(t, ok)
}

func TestStdioSessionManager_ConcurrentAccess(t *testing.T) {
	mockCreator := func(name string, config *config.MCPClientConfig) (*Client, error) {
		mockClient := new(testutil.MockMCPClient)
		mockClient.On("Close").Return(nil).Maybe()
		return &Client{client: mockClient}, nil
	}

	sm := NewStdioSessionManager(WithClientCreator(mockCreator))
	defer sm.Shutdown()

	config := &config.MCPClientConfig{Command: "echo"}
	info := mcp.Implementation{Name: "test", Version: "1.0"}

	// Run concurrent operations
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			key := SessionKey{
				UserEmail:  "test@example.com",
				ServerName: "server",
				SessionID:  fmt.Sprintf("session-%d", i),
			}

			// Create session
			_, err := sm.GetOrCreateSession(context.Background(), key, config, info, "http://localhost", "")
			assert.NoError(t, err)

			// Get session
			_, ok := sm.GetSession(key)
			assert.True(t, ok)

			// Remove session
			sm.RemoveSession(key)
		}(i)
	}

	wg.Wait()
}

func TestStdioSessionManager_NoLimitsForAnonymous(t *testing.T) {
	mockCreator := func(name string, config *config.MCPClientConfig) (*Client, error) {
		mockClient := new(testutil.MockMCPClient)
		mockClient.On("Close").Return(nil).Maybe()
		return &Client{client: mockClient}, nil
	}

	sm := NewStdioSessionManager(
		WithClientCreator(mockCreator),
		WithMaxPerUser(1), // Very low limit
	)
	defer sm.Shutdown()

	config := &config.MCPClientConfig{Command: "echo"}
	info := mcp.Implementation{Name: "test", Version: "1.0"}

	// Create multiple anonymous sessions (empty userEmail)
	for i := range 5 {
		key := SessionKey{
			UserEmail:  "", // Anonymous
			ServerName: "server",
			SessionID:  fmt.Sprintf("session-%d", i),
		}

		_, err := sm.GetOrCreateSession(context.Background(), key, config, info, "http://localhost", "")
		require.NoError(t, err, "Anonymous session %d should succeed", i)
	}
}
