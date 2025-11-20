package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// getDockerComposeCommand returns the appropriate docker compose command
func getDockerComposeCommand() string {
	// Check if docker compose v2 is available
	cmd := exec.Command("docker", "compose", "version")
	if err := cmd.Run(); err == nil {
		return "docker compose"
	}
	return "docker-compose"
}

// execDockerCompose executes docker compose with the given arguments
func execDockerCompose(args ...string) *exec.Cmd {
	dcCmd := getDockerComposeCommand()
	if dcCmd == "docker compose" {
		allArgs := append([]string{"compose"}, args...)
		return exec.Command("docker", allArgs...)
	}
	return exec.Command("docker-compose", args...)
}

// MCPSSEClient simulates an MCP client for testing
type MCPSSEClient struct {
	baseURL         string
	token           string
	sseConn         io.ReadCloser
	messageEndpoint string
	sseScanner      *bufio.Scanner
	sessionID       string
}

// NewMCPSSEClient creates a new MCP client for testing
func NewMCPSSEClient(baseURL string) *MCPSSEClient {
	return &MCPSSEClient{
		baseURL: baseURL,
	}
}

// Authenticate sets up authentication for the client
func (c *MCPSSEClient) Authenticate() error {
	c.token = "test-token"
	return nil
}

// SetAuthToken sets a specific auth token for the client
func (c *MCPSSEClient) SetAuthToken(token string) {
	c.token = token
}

// Connect establishes an SSE connection and retrieves the message endpoint
func (c *MCPSSEClient) Connect() error {
	return c.ConnectToServer("postgres")
}

// ConnectToServer establishes an SSE connection to a specific server
func (c *MCPSSEClient) ConnectToServer(serverName string) error {
	// Close any existing connection
	if c.sseConn != nil {
		c.sseConn.Close()
		c.sseConn = nil
		c.messageEndpoint = ""
	}

	sseURL := c.baseURL + "/" + serverName + "/sse"
	tracef("ConnectToServer: requesting %s", sseURL)

	req, err := http.NewRequest("GET", sseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create SSE request: %v", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Cache-Control", "no-cache")
	tracef("ConnectToServer: headers set, making request")

	// Don't use a timeout on the client for SSE
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connection failed: %v", err)
	}

	tracef("ConnectToServer: got response status %d", resp.StatusCode)
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("SSE connection returned %d: %s", resp.StatusCode, string(body))
	}

	// Store the connection
	c.sseConn = resp.Body
	c.sseScanner = bufio.NewScanner(resp.Body)

	// Read initial SSE messages to get the endpoint
	// For inline servers, we don't get a message endpoint - we use the server path directly
	gotEndpointMessage := false
	for c.sseScanner.Scan() {
		line := c.sseScanner.Text()
		tracef("ConnectToServer: SSE line: %s", line)

		// Look for data lines
		if after, ok := strings.CutPrefix(line, "data: "); ok {
			data := after

			// Check if it's an endpoint message (for inline servers)
			if strings.Contains(data, `"type":"endpoint"`) {
				gotEndpointMessage = true
				// For inline servers, construct the message endpoint
				c.messageEndpoint = c.baseURL + "/" + serverName + "/message"
				tracef("ConnectToServer: inline server detected, using endpoint: %s", c.messageEndpoint)
				break
			}

			// Check if it's a message endpoint URL (for stdio servers)
			if strings.Contains(data, "http://") || strings.Contains(data, "https://") {
				c.messageEndpoint = data

				// Extract session ID from endpoint URL
				if u, err := url.Parse(data); err == nil {
					c.sessionID = u.Query().Get("sessionId")
				}

				tracef("ConnectToServer: found endpoint: %s", c.messageEndpoint)
				break
			}
		}
	}

	if c.messageEndpoint == "" && !gotEndpointMessage {
		c.sseConn.Close()
		c.sseConn = nil
		return fmt.Errorf("no message endpoint received")
	}

	tracef("Connect: successfully connected to MCP server")
	return nil
}

// ValidateBackendConnectivity checks if we can connect to the MCP server
func (c *MCPSSEClient) ValidateBackendConnectivity() error {
	return c.Connect()
}

// Close closes the SSE connection
func (c *MCPSSEClient) Close() {
	if c.sseConn != nil {
		c.sseConn.Close()
		c.sseConn = nil
		c.messageEndpoint = ""
		c.sseScanner = nil
	}
}

// SendMCPRequest sends an MCP JSON-RPC request and returns the response
func (c *MCPSSEClient) SendMCPRequest(method string, params any) (map[string]any, error) {
	// Ensure we have a connection
	if c.messageEndpoint == "" {
		if err := c.Connect(); err != nil {
			return nil, fmt.Errorf("failed to connect: %v", err)
		}
	}

	// Send MCP request to the message endpoint
	request := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	msgReq, err := http.NewRequest("POST", c.messageEndpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	msgReq.Header.Set("Content-Type", "application/json")
	msgReq.Header.Set("Authorization", "Bearer "+c.token)

	client := &http.Client{Timeout: 30 * time.Second}
	msgResp, err := client.Do(msgReq)
	if err != nil {
		return nil, err
	}
	defer msgResp.Body.Close()

	respBody, err := io.ReadAll(msgResp.Body)
	if err != nil {
		return nil, err
	}

	if msgResp.StatusCode != 200 && msgResp.StatusCode != 202 {
		return nil, fmt.Errorf("MCP request failed: %d - %s", msgResp.StatusCode, string(respBody))
	}

	// Handle 202 and empty responses - read response from SSE stream
	if msgResp.StatusCode == 202 || len(respBody) == 0 {
		// Read response from SSE stream
		for c.sseScanner.Scan() {
			line := c.sseScanner.Text()

			if after, ok := strings.CutPrefix(line, "data: "); ok {
				data := after
				// Try to parse as JSON
				var msg map[string]any
				if err := json.Unmarshal([]byte(data), &msg); err == nil {
					// Check if this is our response (matching ID)
					if id, ok := msg["id"]; ok && id == float64(1) {
						return msg, nil
					}
				}
			}
		}

		if err := c.sseScanner.Err(); err != nil {
			return nil, fmt.Errorf("SSE scanner error: %v", err)
		}

		return nil, fmt.Errorf("no response received from SSE stream")
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v - %s", err, string(respBody))
	}

	return result, nil
}

// MCPStreamableClient is a test client for HTTP-Streamable MCP servers
type MCPStreamableClient struct {
	baseURL    string
	serverName string
	token      string
	httpClient *http.Client

	// For GET SSE streaming
	sseConn    io.ReadCloser
	sseScanner *bufio.Scanner
	sseCancel  chan struct{}

	mu sync.Mutex
}

// NewMCPStreamableClient creates a new streamable-http test client
func NewMCPStreamableClient(baseURL string) *MCPStreamableClient {
	return &MCPStreamableClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetAuthToken sets the authentication token
func (c *MCPStreamableClient) SetAuthToken(token string) {
	c.token = token
}

// ConnectToServer establishes connection to a streamable-http server
func (c *MCPStreamableClient) ConnectToServer(serverName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close any existing connection
	c.close()

	c.serverName = serverName

	// For streamable-http, we can optionally open a GET SSE stream for server-initiated messages
	// But it's not required for basic request/response
	return c.openSSEStream()
}

// openSSEStream opens a GET SSE connection for receiving server-initiated messages
func (c *MCPStreamableClient) openSSEStream() error {
	url := c.baseURL + "/" + c.serverName + "/sse"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create GET request: %v", err)
	}

	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Cache-Control", "no-cache")

	// Use a client without timeout for SSE
	sseClient := &http.Client{}
	resp, err := sseClient.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connection failed: %v", err)
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("SSE connection returned %d: %s", resp.StatusCode, string(body))
	}

	c.sseConn = resp.Body
	c.sseScanner = bufio.NewScanner(resp.Body)
	c.sseCancel = make(chan struct{})

	// Start reading SSE messages in background
	go c.readSSEMessages()

	return nil
}

// readSSEMessages reads server-initiated messages from the SSE stream
func (c *MCPStreamableClient) readSSEMessages() {
	for {
		select {
		case <-c.sseCancel:
			return
		default:
			if c.sseScanner.Scan() {
				line := c.sseScanner.Text()
				if after, ok := strings.CutPrefix(line, "data: "); ok {
					data := after
					// In a real implementation, we'd process server-initiated messages here
					tracef("StreamableClient: received SSE message: %s", data)
				}
			} else {
				// Scanner stopped - connection closed or error
				return
			}
		}
	}
}

// SendMCPRequest sends a JSON-RPC request via POST
func (c *MCPStreamableClient) SendMCPRequest(method string, params any) (map[string]any, error) {
	c.mu.Lock()
	serverName := c.serverName
	c.mu.Unlock()

	if serverName == "" {
		return nil, fmt.Errorf("not connected to any server")
	}

	// For streamable-http, we POST to the server endpoint
	url := c.baseURL + "/" + serverName + "/sse"

	// Construct JSON-RPC request
	request := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	// Accept both JSON and SSE responses
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check content type to determine response format
	contentType := resp.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "text/event-stream") {
		// Handle SSE response
		return c.handleSSEResponse(resp.Body)
	} else {
		// Handle JSON response
		return c.handleJSONResponse(resp.Body)
	}
}

// handleJSONResponse processes a regular JSON response
func (c *MCPStreamableClient) handleJSONResponse(body io.Reader) (map[string]any, error) {
	var response map[string]any
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}
	return response, nil
}

// handleSSEResponse processes an SSE stream response from a POST
func (c *MCPStreamableClient) handleSSEResponse(body io.Reader) (map[string]any, error) {
	scanner := bufio.NewScanner(body)
	var lastResponse map[string]any

	for scanner.Scan() {
		line := scanner.Text()
		if after, ok := strings.CutPrefix(line, "data: "); ok {
			data := after
			var msg map[string]any
			if err := json.Unmarshal([]byte(data), &msg); err == nil {
				// Keep the last response with an ID (not a notification)
				if _, hasID := msg["id"]; hasID {
					lastResponse = msg
				}
			}
		}
	}

	if lastResponse == nil {
		return nil, fmt.Errorf("no response received in SSE stream")
	}

	return lastResponse, nil
}

// Close closes all connections
func (c *MCPStreamableClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.close()
}

// close is the internal close method (must be called with lock held)
func (c *MCPStreamableClient) close() {
	if c.sseCancel != nil {
		close(c.sseCancel)
		c.sseCancel = nil
	}

	if c.sseConn != nil {
		c.sseConn.Close()
		c.sseConn = nil
		c.sseScanner = nil
	}

	c.serverName = ""
}

// FakeGCPServer provides a fake GCP OAuth server for testing
type FakeGCPServer struct {
	server *http.Server
	port   string
}

// NewFakeGCPServer creates a new fake GCP server
func NewFakeGCPServer(port string) *FakeGCPServer {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, fmt.Sprintf("%s?code=test-auth-code&state=%s", redirectURI, state), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Parse the form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Check the authorization code
		code := r.FormValue("code")
		if code != "test-auth-code" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             "invalid_grant",
				"error_description": "Invalid authorization code",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"email": "test@test.com",
			"hd":    "test.com",
		})
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	return &FakeGCPServer{
		server: server,
		port:   port,
	}
}

// Start starts the fake GCP server
func (m *FakeGCPServer) Start() error {
	go func() {
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

// Stop stops the fake GCP server
func (m *FakeGCPServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.server.Shutdown(ctx)
}

// FakeServiceOAuthServer provides a fake OAuth server for external services (like Linear, GitHub)
type FakeServiceOAuthServer struct {
	server *http.Server
	port   string
}

// NewFakeServiceOAuthServer creates a new fake service OAuth server
func NewFakeServiceOAuthServer(port string) *FakeServiceOAuthServer {
	mux := http.NewServeMux()

	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, fmt.Sprintf("%s?code=service-auth-code&state=%s", redirectURI, state), http.StatusFound)
	})

	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		if code != "service-auth-code" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             "invalid_grant",
				"error_description": "Invalid authorization code",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "service-oauth-access-token",
			"refresh_token": "service-oauth-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	return &FakeServiceOAuthServer{
		server: server,
		port:   port,
	}
}

// Start starts the fake service OAuth server
func (s *FakeServiceOAuthServer) Start() error {
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

// Stop stops the fake service OAuth server
func (s *FakeServiceOAuthServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// TestEnvironment manages the complete test environment
type TestEnvironment struct {
	dbCmd   *exec.Cmd
	mcpCmd  *exec.Cmd
	fakeGCP *FakeGCPServer
	client  *MCPSSEClient
}

// SetupTestEnvironment creates and starts all components needed for testing
func SetupTestEnvironment(t *testing.T) *TestEnvironment {
	env := &TestEnvironment{}

	// Start test database
	t.Log("🚀 Starting test database...")
	env.dbCmd = execDockerCompose("-f", "config/docker-compose.test.yml", "up", "-d")
	if err := env.dbCmd.Run(); err != nil {
		t.Fatalf("Failed to start test database: %v", err)
	}

	time.Sleep(10 * time.Second)

	// Start mock GCP server
	t.Log("🚀 Starting mock GCP server...")
	env.fakeGCP = NewFakeGCPServer("9090")
	if err := env.fakeGCP.Start(); err != nil {
		t.Fatalf("Failed to start mock GCP server: %v", err)
	}

	// Start mcp-front
	t.Log("🚀 Starting mcp-front...")
	env.mcpCmd = exec.Command("../cmd/mcp-front/mcp-front", "-config", "config/config.test.json")

	// Capture stderr to log file if MCP_LOG_FILE is set
	if logFile := os.Getenv("MCP_LOG_FILE"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			env.mcpCmd.Stderr = f
			env.mcpCmd.Stdout = f
			t.Cleanup(func() { f.Close() })
		}
	}

	if err := env.mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}

	time.Sleep(15 * time.Second)

	// Create and authenticate client
	env.client = NewMCPSSEClient("http://localhost:8080")
	if err := env.client.Authenticate(); err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	return env
}

// Cleanup stops all test environment components
func (env *TestEnvironment) Cleanup() {
	if env.mcpCmd != nil && env.mcpCmd.Process != nil {
		_ = env.mcpCmd.Process.Kill()
	}

	if env.fakeGCP != nil {
		_ = env.fakeGCP.Stop()
	}

	if env.dbCmd != nil {
		downCmd := execDockerCompose("-f", "config/docker-compose.test.yml", "down", "-v")
		_ = downCmd.Run()
	}
}

// TestConfig holds all timeout configurations for integration tests
type TestConfig struct {
	SessionTimeout     string
	CleanupInterval    string
	CleanupWaitTime    string
	TimerResetWaitTime string
	MultiUserWaitTime  string
}

// GetTestConfig returns test configuration from environment variables or defaults
func GetTestConfig() TestConfig {
	c := TestConfig{
		SessionTimeout:     "10s",
		CleanupInterval:    "2s",
		CleanupWaitTime:    "15s",
		TimerResetWaitTime: "12s",
		MultiUserWaitTime:  "15s",
	}

	// Override from environment if set
	if v := os.Getenv("SESSION_TIMEOUT"); v != "" {
		c.SessionTimeout = v
	}
	if v := os.Getenv("SESSION_CLEANUP_INTERVAL"); v != "" {
		c.CleanupInterval = v
	}
	if v := os.Getenv("TEST_CLEANUP_WAIT_TIME"); v != "" {
		c.CleanupWaitTime = v
	}
	if v := os.Getenv("TEST_TIMER_RESET_WAIT_TIME"); v != "" {
		c.TimerResetWaitTime = v
	}
	if v := os.Getenv("TEST_MULTI_USER_WAIT_TIME"); v != "" {
		c.MultiUserWaitTime = v
	}

	return c
}

func waitForDB(t *testing.T) {
	waitForSec := 5
	for range waitForSec {
		// Check if container is running
		psCmd := exec.Command("docker", "compose", "ps", "-q", "test-postgres")
		if output, err := psCmd.Output(); err != nil || len(output) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}

		// Check if database is ready
		checkCmd := exec.Command("docker", "compose", "exec", "-T", "test-postgres", "pg_isready", "-U", "testuser", "-d", "testdb")
		if err := checkCmd.Run(); err == nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	t.Fatalf("Database failed to become ready after %d seconds", waitForSec)
}

// trace logs a message if TRACE environment variable is set
func trace(t *testing.T, format string, args ...any) {
	if os.Getenv("TRACE") == "1" {
		t.Logf("TRACE: "+format, args...)
	}
}

// tracef logs a formatted message to stdout if TRACE is set (for use outside tests)
func tracef(format string, args ...any) {
	if os.Getenv("TRACE") == "1" {
		fmt.Printf("TRACE: "+format+"\n", args...)
	}
}

// startMCPFront starts the mcp-front server with the given config
func startMCPFront(t *testing.T, configPath string, extraEnv ...string) {
	mcpCmd := exec.Command("../cmd/mcp-front/mcp-front", "-config", configPath)

	// Get test config for session timeouts
	testConfig := GetTestConfig()

	// Build default environment with test timeouts
	defaultEnv := []string{
		"SESSION_TIMEOUT=" + testConfig.SessionTimeout,
		"SESSION_CLEANUP_INTERVAL=" + testConfig.CleanupInterval,
	}

	// Start with system environment
	mcpCmd.Env = os.Environ()

	// Apply defaults first
	mcpCmd.Env = append(mcpCmd.Env, defaultEnv...)

	// Apply extra env (can override defaults)
	mcpCmd.Env = append(mcpCmd.Env, extraEnv...)

	// Pass through LOG_LEVEL and LOG_FORMAT if set
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		mcpCmd.Env = append(mcpCmd.Env, "LOG_LEVEL="+logLevel)
	}
	if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
		mcpCmd.Env = append(mcpCmd.Env, "LOG_FORMAT="+logFormat)
	}

	// Capture output to log file if MCP_LOG_FILE is set
	if logFile := os.Getenv("MCP_LOG_FILE"); logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			mcpCmd.Stderr = f
			mcpCmd.Stdout = f
			t.Cleanup(func() { f.Close() })
		}
	}

	if err := mcpCmd.Start(); err != nil {
		t.Fatalf("Failed to start mcp-front: %v", err)
	}

	// Register cleanup that runs even if test is killed
	t.Cleanup(func() {
		stopMCPFront(mcpCmd)
	})
}

// stopMCPFront stops the mcp-front server gracefully
func stopMCPFront(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	// Try graceful shutdown first (SIGINT)
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		// If SIGINT fails, force kill immediately
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return
	}

	// Wait up to 5 seconds for graceful shutdown
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		// Graceful shutdown completed
		return
	case <-time.After(5 * time.Second):
		// Timeout, force kill
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// waitForMCPFront waits for the mcp-front server to be ready
func waitForMCPFront(t *testing.T) {
	t.Helper()
	for range 10 {
		resp, err := http.Get("http://localhost:8080/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("mcp-front failed to become ready after 10 seconds")
}

// getMCPContainers returns a list of running mcp/postgres container IDs
func getMCPContainers() []string {
	cmd := exec.Command("docker", "ps", "--format", "{{.ID}}", "--filter", "ancestor=mcp/postgres")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var containers []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line != "" {
			containers = append(containers, line)
		}
	}
	return containers
}

// cleanupContainers forces cleanup of containers that weren't in the initial set
func cleanupContainers(t *testing.T, initialContainers []string) {
	time.Sleep(2 * time.Second)
	containers := getMCPContainers()
	for _, container := range containers {
		isInitial := slices.Contains(initialContainers, container)
		if !isInitial {
			t.Logf("Force stopping container: %s...", container)
			if err := exec.Command("docker", "stop", container).Run(); err != nil {
				t.Logf("Failed to stop container %s: %v", container, err)
			} else {
				t.Logf("Stopped container: %s", container)
			}
		}
	}
}

// TestQuickSmoke provides a fast validation test
func TestQuickSmoke(t *testing.T) {
	t.Log("Running quick smoke test...")

	// Just verify the test infrastructure works
	client := NewMCPSSEClient("http://localhost:8080")
	if client == nil {
		t.Fatal("Failed to create client")
	}

	if err := client.Authenticate(); err != nil {
		t.Fatal("Failed to set up authentication")
	}

	t.Log("Quick smoke test passed - test infrastructure is working")
}
