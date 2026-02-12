package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

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
