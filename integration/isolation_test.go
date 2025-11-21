package integration

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiUserSessionIsolation validates that multiple users have separate stdio instances
func TestMultiUserSessionIsolation(t *testing.T) {
	trace(t, "Starting multi-user session isolation test")

	// Database is already started by TestMain, just wait for readiness
	waitForDB(t)

	// Start mcp-front with bearer token auth
	trace(t, "Starting mcp-front")
	startMCPFront(t, "config/config.test.json")
	waitForMCPFront(t)

	// Get initial container count
	initialContainers := getMCPContainers()
	t.Logf("Initial mcp/postgres containers: %d", len(initialContainers))

	// Create two clients with different auth tokens
	client1 := NewMCPSSEClient("http://localhost:8080")
	client1.SetAuthToken("test-token") // First user
	defer client1.Close()

	client2 := NewMCPSSEClient("http://localhost:8080")
	client2.SetAuthToken("alt-test-token") // Second user
	defer client2.Close()

	// Add cleanup to ensure containers are stopped at test end
	t.Cleanup(func() {
		cleanupContainers(t, initialContainers)
	})

	// Step 1: First user connects and sends a query
	t.Log("Step 1: First user connects and sends a query")
	if err := client1.Connect(); err != nil {
		t.Fatalf("Client1 failed to connect: %v", err)
	}
	t.Logf("Client1 connected with session: %s", client1.sessionID)

	containersAfterClient1 := getMCPContainers()
	t.Logf("Containers after client1 connects: %d", len(containersAfterClient1))
	assert.Greater(t, len(containersAfterClient1), len(initialContainers), "No new container created after client1 connects")

	// Find new container for client1
	var client1Container string
	for _, container := range containersAfterClient1 {
		isNew := true
		if slices.Contains(initialContainers, container) {
			isNew = false
		}
		if isNew {
			client1Container = container
			t.Logf("Client1 got new container: %s", container)
			break
		}
	}

	if client1Container == "" {
		t.Error("No new container created for client1")
	}

	query1Result, err := client1.SendMCPRequest("tools/call", map[string]any{
		"name": "query",
		"arguments": map[string]any{
			"sql": "SELECT 'user1-query1' as test_id, COUNT(*) as count FROM users",
		},
	})
	if err != nil {
		t.Fatalf("Client1 query 1 failed: %v", err)
	}
	t.Logf("Client1 query 1 result: %+v", query1Result)

	// Step 2: Second user connects and sends a query
	t.Log("\nStep 2: Second user connects and sends a query")
	if err := client2.Connect(); err != nil {
		t.Fatalf("Client2 failed to connect: %v", err)
	}
	t.Logf("Client2 connected with session: %s", client2.sessionID)

	// Verify different sessions
	if client1.sessionID == client2.sessionID {
		t.Errorf("Expected different sessions for different users, but both got: %s", client1.sessionID)
	}

	containersAfterClient2 := getMCPContainers()
	t.Logf("Containers after client2 connects: %d", len(containersAfterClient2))
	assert.Greater(t, len(containersAfterClient2), len(containersAfterClient1), "No new container created after client2 connects")

	// Find new container for client2
	var client2Container string
	for _, container := range containersAfterClient2 {
		isNew := true
		if slices.Contains(containersAfterClient1, container) {
			isNew = false
		}
		if isNew {
			client2Container = container
			t.Logf("Client2 got new container: %s", container)
			break
		}
	}

	if client2Container == "" {
		t.Error("No new container created for client2")
	}

	// Verify that client1 and client2 have different containers
	if client1Container != "" && client2Container != "" && client1Container == client2Container {
		t.Errorf("CRITICAL: Both users are using the same Docker container! Container ID: %s", client1Container)
		t.Error("This indicates session isolation is NOT working - users are sharing the same mcp/postgres instance")
	} else if client1Container != "" && client2Container != "" {
		t.Logf("Confirmed different stdio processes: User1 container=%s, User2 container=%s", client1Container, client2Container)
	}

	query2Result, err := client2.SendMCPRequest("tools/call", map[string]any{
		"name": "query",
		"arguments": map[string]any{
			"sql": "SELECT 'user2-query1' as test_id, COUNT(*) as count FROM orders",
		},
	})
	if err != nil {
		t.Fatalf("Client2 query 1 failed: %v", err)
	}
	t.Logf("Client2 query 1 result: %+v", query2Result)

	// Step 3: First user sends another query
	t.Log("\nStep 3: First user sends another query")
	query3Result, err := client1.SendMCPRequest("tools/call", map[string]any{
		"name": "query",
		"arguments": map[string]any{
			"sql": "SELECT 'user1-query2' as test_id, current_timestamp as ts",
		},
	})
	if err != nil {
		t.Fatalf("Client1 query 2 failed: %v", err)
	}
	t.Logf("Client1 query 2 result: %+v", query3Result)

	// Step 4: First user sends another query
	t.Log("\nStep 4: First user sends another query")
	query4Result, err := client1.SendMCPRequest("tools/call", map[string]any{
		"name": "query",
		"arguments": map[string]any{
			"sql": "SELECT 'user1-query3' as test_id, version() as db_version",
		},
	})
	if err != nil {
		t.Fatalf("Client1 query 3 failed: %v", err)
	}
	t.Logf("Client1 query 3 result: %+v", query4Result)

	// Step 5: Second user sends a query
	t.Log("\nStep 5: Second user sends a query")
	query5Result, err := client2.SendMCPRequest("tools/call", map[string]any{
		"name": "query",
		"arguments": map[string]any{
			"sql": "SELECT 'user2-query2' as test_id, current_database() as db_name",
		},
	})
	if err != nil {
		t.Fatalf("Client2 query 2 failed: %v", err)
	}
	t.Logf("Client2 query 2 result: %+v", query5Result)

	// Final verification
	finalContainers := getMCPContainers()
	t.Log("\n=== Container Summary ===")
	t.Logf("Initial containers: %d", len(initialContainers))
	t.Logf("Final containers: %d", len(finalContainers))
	t.Logf("New containers created: %d", len(finalContainers)-len(initialContainers))

	expectedNewContainers := 2
	actualNewContainers := len(finalContainers) - len(initialContainers)
	assert.Equal(t, expectedNewContainers, actualNewContainers, "Expected exactly 2 new containers (one for each user)")

	// Verify session isolation
	t.Log("\n=== Session Isolation Summary ===")
	t.Logf("Client1 session: %s", client1.sessionID)
	t.Logf("Client2 session: %s", client2.sessionID)
	if client1Container != "" {
		t.Logf("Client1 container: %s", client1Container)
	}
	if client2Container != "" {
		t.Logf("Client2 container: %s", client2Container)
	}

	assert.NotEqual(t, client1.sessionID, client2.sessionID, "Users should have different sessions")
	assert.NotEmpty(t, client1Container, "Client1 should have a container")
	assert.NotEmpty(t, client2Container, "Client2 should have a container")
	assert.NotEqual(t, client1Container, client2Container, "Users should have different stdio containers")
}

// TestSessionCleanupAfterTimeout verifies that sessions and containers are cleaned up after timeout
func TestSessionCleanupAfterTimeout(t *testing.T) {
	trace(t, "Starting session cleanup timeout test")

	// Database is already started by TestMain, just wait for readiness
	waitForDB(t)

	// Start mcp-front with test timeout configuration
	trace(t, "Starting mcp-front with test session timeout")
	startMCPFront(t, "config/config.test.json")
	waitForMCPFront(t)

	// Get initial container count
	initialContainers := getMCPContainers()
	t.Logf("Initial mcp/postgres containers: %d", len(initialContainers))

	// Create a client and connect
	client := NewMCPSSEClient("http://localhost:8080")
	client.SetAuthToken("test-token")

	// Add cleanup for this test
	t.Cleanup(func() {
		cleanupContainers(t, initialContainers)
	})

	t.Log("Connecting client...")
	err := client.Connect()
	require.NoError(t, err, "Client failed to connect")
	t.Logf("Client connected with session: %s", client.sessionID)

	// Verify container was created
	containersAfterConnect := getMCPContainers()
	t.Logf("Containers after connect: %d", len(containersAfterConnect))

	assert.Greater(t, len(containersAfterConnect), len(initialContainers), "No new container created for client")

	// Send a query to ensure session is active
	_, err = client.SendMCPRequest("tools/call", map[string]any{
		"name": "query",
		"arguments": map[string]any{
			"sql": "SELECT 'test' as test_id",
		},
	})
	require.NoError(t, err, "Query failed")

	// Close the client connection (but don't remove the session)
	client.Close()
	t.Log("Client connection closed, session should remain active")

	// Verify container is still there immediately after close
	containersAfterClose := getMCPContainers()
	t.Logf("Containers immediately after close: %d", len(containersAfterClose))

	assert.GreaterOrEqual(t, len(containersAfterClose), len(containersAfterConnect),
		"Container was removed immediately after close (should remain until timeout)")

	// Wait for timeout + cleanup interval
	testConfig := GetTestConfig()
	waitTime, _ := time.ParseDuration(testConfig.CleanupWaitTime)
	t.Logf("Waiting %v for session timeout and cleanup...", waitTime)
	time.Sleep(waitTime)

	containersAfterTimeout := getMCPContainers()
	t.Logf("Containers after timeout: %d", len(containersAfterTimeout))

	assert.Equal(t, len(initialContainers), len(containersAfterTimeout),
		"Container should be cleaned up after session timeout")
}

// TestSessionTimerReset verifies that using a session resets its timeout timer
func TestSessionTimerReset(t *testing.T) {
	trace(t, "Starting session timer reset test")

	// Database is already started by TestMain, just wait for readiness
	waitForDB(t)

	// Start mcp-front with test timeout configuration
	trace(t, "Starting mcp-front with test session timeout")
	startMCPFront(t, "config/config.test.json")
	waitForMCPFront(t)

	// Get initial container count
	initialContainers := getMCPContainers()
	t.Logf("Initial mcp/postgres containers: %d", len(initialContainers))

	// Create a client and connect
	client := NewMCPSSEClient("http://localhost:8080")
	client.SetAuthToken("test-token")

	// Add cleanup for this test
	t.Cleanup(func() {
		cleanupContainers(t, initialContainers)
	})

	t.Log("Connecting client...")
	if err := client.Connect(); err != nil {
		t.Fatalf("Client failed to connect: %v", err)
	}
	t.Logf("Client connected with session: %s", client.sessionID)

	containersAfterConnect := getMCPContainers()
	assert.Greater(t, len(containersAfterConnect), len(initialContainers),
		"No new container created for client")

	// Keep session alive by sending queries every 5 seconds
	// With 8s timeout, this should keep it alive
	for i := range 3 {
		t.Logf("Sending keepalive query %d/3...", i+1)
		_, err := client.SendMCPRequest("tools/call", map[string]any{
			"name": "query",
			"arguments": map[string]any{
				"sql": "SELECT 'keepalive' as status, NOW() as timestamp",
			},
		})
		if err != nil {
			t.Fatalf("Keepalive query %d failed: %v", i+1, err)
		}

		// Wait 5 seconds before next query
		if i < 2 {
			time.Sleep(5 * time.Second)
		}
	}

	t.Log("Checking if container is still active after keepalive queries...")

	containersAfterKeepalive := getMCPContainers()
	t.Logf("Containers after keepalive: %d", len(containersAfterKeepalive))

	assert.GreaterOrEqual(t, len(containersAfterKeepalive), len(containersAfterConnect),
		"Container should remain active due to keepalive queries (timer reset)")

	// Now stop sending queries and close the connection
	t.Log("Stopping keepalive queries and closing connection...")
	client.Close()

	// Wait for timeout
	testConfig := GetTestConfig()
	waitTime, _ := time.ParseDuration(testConfig.TimerResetWaitTime)
	t.Logf("Waiting %v for session timeout...", waitTime)
	time.Sleep(waitTime)

	containersAfterTimeout := getMCPContainers()
	t.Logf("Containers after timeout: %d", len(containersAfterTimeout))

	assert.Equal(t, len(initialContainers), len(containersAfterTimeout),
		"Container should be cleaned up after inactivity timeout")
}

// TestMultiUserTimerIndependence verifies that each user's session timer is independent
func TestMultiUserTimerIndependence(t *testing.T) {
	trace(t, "Starting multi-user timer independence test")

	// Database is already started by TestMain, just wait for readiness
	waitForDB(t)

	// Start mcp-front with test timeout configuration
	trace(t, "Starting mcp-front with test session timeout")
	startMCPFront(t, "config/config.test.json")
	waitForMCPFront(t)

	// Get initial container count
	initialContainers := getMCPContainers()
	t.Logf("Initial mcp/postgres containers: %d", len(initialContainers))

	// Create two clients
	client1 := NewMCPSSEClient("http://localhost:8080")
	client1.SetAuthToken("test-token")

	client2 := NewMCPSSEClient("http://localhost:8080")
	client2.SetAuthToken("alt-test-token")

	// Add cleanup for this test
	t.Cleanup(func() {
		cleanupContainers(t, initialContainers)
	})

	// Connect both clients
	t.Log("Connecting client1...")
	if err := client1.Connect(); err != nil {
		t.Fatalf("Client1 failed to connect: %v", err)
	}
	t.Logf("Client1 connected with session: %s", client1.sessionID)

	// Wait a bit before connecting client2
	time.Sleep(3 * time.Second)

	t.Log("Connecting client2...")
	if err := client2.Connect(); err != nil {
		t.Fatalf("Client2 failed to connect: %v", err)
	}
	t.Logf("Client2 connected with session: %s", client2.sessionID)

	// Verify both containers exist
	containersAfterBothConnect := getMCPContainers()
	assert.Equal(t, len(initialContainers)+2, len(containersAfterBothConnect),
		"Should have 2 new containers (one for each client)")

	// Keep client2 active while letting client1 timeout
	t.Log("Keeping client2 active while client1 becomes idle...")

	// Close client1's connection to make it idle
	client1.Close()

	// Keep client2 active with periodic queries
	done := make(chan bool)
	go func() {
		defer close(done)
		// Run 4 queries - the last one AFTER client1 should be cleaned up
		for i := range 4 {
			time.Sleep(4 * time.Second)
			_, err := client2.SendMCPRequest("tools/call", map[string]any{
				"name": "query",
				"arguments": map[string]any{
					"sql": "SELECT 'client2-keepalive' as status",
				},
			})
			if err != nil {
				t.Logf("Client2 keepalive query %d failed: %v", i+1, err)
			} else {
				t.Logf("Client2 keepalive query %d succeeded", i+1)
			}
		}
	}()

	// Wait for client1's timeout
	testConfig := GetTestConfig()
	waitTime, _ := time.ParseDuration(testConfig.MultiUserWaitTime)
	t.Logf("Waiting %v for client1 timeout while client2 stays active...", waitTime)
	time.Sleep(waitTime)

	containersAfterClient1Timeout := getMCPContainers()
	t.Logf("Containers after client1 timeout: %d", len(containersAfterClient1Timeout))

	expectedContainers := len(initialContainers) + 1 // Only client2's container
	assert.Equal(t, expectedContainers, len(containersAfterClient1Timeout),
		"Client1's container should be cleaned up, only client2's should remain")

	// Wait for the keepalive goroutine to finish (including the 4th query)
	<-done

	t.Log("All keepalive queries completed - client2 remained active throughout")

	// Clean up client2
	client2.Close()
}
