package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ToolboxImage is the Docker image for the MCP Toolbox for Databases.
// Used as the MCP server backing integration tests. All test configs
// that reference a postgres MCP server should use this image.
const ToolboxImage = "us-central1-docker.pkg.dev/database-toolbox/toolbox/toolbox:latest"

// testPostgresDockerArgs returns the Docker args for running the toolbox
// as a stdio MCP server against the test postgres database.
func testPostgresDockerArgs() []string {
	return []string{
		"run", "--rm", "-i", "--network", "host",
		"-e", "POSTGRES_HOST=localhost",
		"-e", "POSTGRES_PORT=15432",
		"-e", "POSTGRES_DATABASE=testdb",
		"-e", "POSTGRES_USER=testuser",
		"-e", "POSTGRES_PASSWORD=testpass",
		ToolboxImage,
		"--stdio", "--prebuilt", "postgres",
	}
}

// testPostgresServer returns an MCP server config for the test postgres database.
// Options can customize auth, logging, etc.
func testPostgresServer(opts ...serverOption) map[string]any {
	args := make([]any, len(testPostgresDockerArgs()))
	for i, a := range testPostgresDockerArgs() {
		args[i] = a
	}
	s := map[string]any{
		"transportType": "stdio",
		"command":       "docker",
		"args":          args,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type serverOption func(map[string]any)

func withBearerTokens(tokens ...string) serverOption {
	return func(s map[string]any) {
		s["serviceAuths"] = []map[string]any{
			{"type": "bearer", "tokens": tokens},
		}
	}
}

func withBasicAuth(username, passwordEnvVar string) serverOption {
	return func(s map[string]any) {
		auths, _ := s["serviceAuths"].([]map[string]any)
		auths = append(auths, map[string]any{
			"type":     "basic",
			"username": username,
			"password": map[string]string{"$env": passwordEnvVar},
		})
		s["serviceAuths"] = auths
	}
}

func withLogEnabled() serverOption {
	return func(s map[string]any) {
		s["options"] = map[string]any{"logEnabled": true}
	}
}

func withUserToken() serverOption {
	return func(s map[string]any) {
		s["env"] = map[string]any{
			"USER_TOKEN": map[string]string{"$userToken": "{{token}}"},
		}
		s["requiresUserToken"] = true
		s["userAuthentication"] = map[string]any{
			"type":         "manual",
			"displayName":  "Test Service",
			"instructions": "Enter your test token",
			"helpUrl":      "https://example.com/help",
		}
	}
}

// testOAuthConfigFromEnv returns an OAuth auth config that reads secrets from env vars.
func testOAuthConfigFromEnv() map[string]any {
	return map[string]any{
		"kind":       "oauth",
		"issuer":     "http://localhost:8080",
		"gcpProject": "test-project",
		"idp": map[string]any{
			"provider":         "google",
			"clientId":         map[string]string{"$env": "GOOGLE_CLIENT_ID"},
			"clientSecret":     map[string]string{"$env": "GOOGLE_CLIENT_SECRET"},
			"redirectUri":      "http://localhost:8080/oauth/callback",
			"authorizationUrl": "http://localhost:9090/auth",
			"tokenUrl":         "http://localhost:9090/token",
			"userInfoUrl":      "http://localhost:9090/userinfo",
		},
		"allowedDomains": []string{"test.com", "stainless.com", "claude.ai"},
		"allowedOrigins": []string{"https://claude.ai"},
		"tokenTtl":       "1h",
		"storage":        "memory",
		"jwtSecret":      map[string]string{"$env": "JWT_SECRET"},
		"encryptionKey":  map[string]string{"$env": "ENCRYPTION_KEY"},
	}
}

// testGitHubOAuthConfig returns an OAuth auth config for GitHub IDP testing.
// Secrets use $env references; callers must pass JWT_SECRET, ENCRYPTION_KEY,
// and GITHUB_CLIENT_SECRET env vars.
func testGitHubOAuthConfig(allowedOrgs ...string) map[string]any {
	idpCfg := map[string]any{
		"provider":         "github",
		"clientId":         "test-github-client-id",
		"clientSecret":     map[string]string{"$env": "GITHUB_CLIENT_SECRET"},
		"redirectUri":      "http://localhost:8080/oauth/callback",
		"authorizationUrl": "http://localhost:9092/login/oauth/authorize",
		"tokenUrl":         "http://localhost:9092/login/oauth/access_token",
		"userInfoUrl":      "http://localhost:9092",
	}
	if len(allowedOrgs) > 0 {
		idpCfg["allowedOrgs"] = allowedOrgs
	}
	return map[string]any{
		"kind":           "oauth",
		"issuer":         "http://localhost:8080",
		"gcpProject":     "test-project",
		"idp":            idpCfg,
		"allowedDomains": []string{"test.com"},
		"allowedOrigins": []string{"https://claude.ai"},
		"tokenTtl":       "1h",
		"storage":        "memory",
		"jwtSecret":      map[string]string{"$env": "JWT_SECRET"},
		"encryptionKey":  map[string]string{"$env": "ENCRYPTION_KEY"},
	}
}

// testOIDCOAuthConfig returns an OAuth auth config for generic OIDC IDP testing.
// Secrets use $env references; callers must pass JWT_SECRET, ENCRYPTION_KEY,
// and OIDC_CLIENT_SECRET env vars.
func testOIDCOAuthConfig() map[string]any {
	return map[string]any{
		"kind":       "oauth",
		"issuer":     "http://localhost:8080",
		"gcpProject": "test-project",
		"idp": map[string]any{
			"provider":         "oidc",
			"clientId":         "test-oidc-client-id",
			"clientSecret":     map[string]string{"$env": "OIDC_CLIENT_SECRET"},
			"redirectUri":      "http://localhost:8080/oauth/callback",
			"authorizationUrl": "http://localhost:9093/authorize",
			"tokenUrl":         "http://localhost:9093/token",
			"userInfoUrl":      "http://localhost:9093/userinfo",
		},
		"allowedDomains": []string{"oidc-test.com"},
		"allowedOrigins": []string{"https://claude.ai"},
		"tokenTtl":       "1h",
		"storage":        "memory",
		"jwtSecret":      map[string]string{"$env": "JWT_SECRET"},
		"encryptionKey":  map[string]string{"$env": "ENCRYPTION_KEY"},
	}
}

// testAzureOAuthConfig returns an OAuth auth config for Azure IDP testing.
// Secrets use $env references; callers must pass JWT_SECRET, ENCRYPTION_KEY,
// and AZURE_CLIENT_SECRET env vars.
func testAzureOAuthConfig() map[string]any {
	return map[string]any{
		"kind":       "oauth",
		"issuer":     "http://localhost:8080",
		"gcpProject": "test-project",
		"idp": map[string]any{
			"provider":         "azure",
			"tenantId":         "test-tenant",
			"clientId":         "test-azure-client-id",
			"clientSecret":     map[string]string{"$env": "AZURE_CLIENT_SECRET"},
			"redirectUri":      "http://localhost:8080/oauth/callback",
			"authorizationUrl": "http://localhost:9093/authorize",
			"tokenUrl":         "http://localhost:9093/token",
			"userInfoUrl":      "http://localhost:9093/userinfo",
		},
		"allowedDomains": []string{"oidc-test.com"},
		"allowedOrigins": []string{"https://claude.ai"},
		"tokenTtl":       "1h",
		"storage":        "memory",
		"jwtSecret":      map[string]string{"$env": "JWT_SECRET"},
		"encryptionKey":  map[string]string{"$env": "ENCRYPTION_KEY"},
	}
}

// writeTestConfig writes a config map to a temporary JSON file and returns its path.
// The file is automatically cleaned up when the test finishes.
func writeTestConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Failed to close temp config: %v", err)
	}
	return f.Name()
}

// buildTestConfig builds a complete mcp-front config map.
func buildTestConfig(baseURL, name string, auth map[string]any, mcpServers map[string]any) map[string]any {
	proxy := map[string]any{
		"baseURL": baseURL,
		"addr":    ":8080",
		"name":    name,
	}
	if auth != nil {
		proxy["auth"] = auth
	}
	return map[string]any{
		"version":    "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
		"proxy":      proxy,
		"mcpServers": mcpServers,
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

// getMCPContainers returns a list of running toolbox container IDs
func getMCPContainers() []string {
	cmd := exec.Command("docker", "ps", "--format", "{{.ID}}", "--filter", "ancestor="+ToolboxImage)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var containers []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
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
