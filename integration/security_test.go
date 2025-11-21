package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityScenarios(t *testing.T) {
	// Database is already started by TestMain, just wait for readiness
	waitForDB(t)

	// Start mcp-front
	startMCPFront(t, "config/config.test.json")

	// Wait for server to be ready
	waitForMCPFront(t)

	t.Run("NoAuthToken", func(t *testing.T) {
		// Test:

		resp, err := http.Get("http://localhost:8080/postgres/sse")
		require.NoError(t, err, "Request failed")
		resp.Body.Close()

		assert.Equal(t, 401, resp.StatusCode, "Expected 401 Unauthorized")
	})

	t.Run("InvalidBearerToken", func(t *testing.T) {
		// Test:

		client := &http.Client{}
		req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-12345")
		req.Header.Set("Accept", "text/event-stream")

		resp, err := client.Do(req)
		require.NoError(t, err, "Request failed")
		resp.Body.Close()

		assert.Equal(t, 401, resp.StatusCode, "Expected 401 Unauthorized")
	})

	t.Run("MalformedAuthHeader", func(t *testing.T) {
		// Test:

		malformedHeaders := []string{
			"Bearer",                           // Missing token
			"Basic test-token",                 // Wrong auth type
			"bearer test-token",                // Wrong case
			"Bearer test-token extra",          // Extra data
			"test-token",                       // Missing Bearer prefix
			"Authorization: Bearer test-token", // Full header as value
		}

		for _, authHeader := range malformedHeaders {
			// Testing malformed header

			client := &http.Client{}
			req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
			req.Header.Set("Authorization", authHeader)
			req.Header.Set("Accept", "text/event-stream")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != 401 {
				t.Errorf("Expected 401 for malformed header '%s', got %d", authHeader, resp.StatusCode)
			}
		}
	})

	t.Run("SQLInjectionAttempts", func(t *testing.T) {
		t.Skip("Skipping SQL injection tests, it's not a responsibility of mcp-front to guard mcp/postgres")

		client := NewMCPSSEClient("http://localhost:8080")
		_ = client.Authenticate()

		// Validate backend connectivity first
		err := client.ValidateBackendConnectivity()
		require.NoError(t, err, "Backend connectivity failed")

		sqlInjectionPayloads := []string{
			"'; DROP TABLE users; --",
			"1; DELETE FROM users WHERE 1=1; --",
			"UNION SELECT * FROM users WHERE 1=1 --",
			"'; INSERT INTO users VALUES ('hacker', 'hack@evil.com'); --",
			"1' OR '1'='1",
			"'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'; --",
		}

		for _, payload := range sqlInjectionPayloads {
			// Testing SQL injection payload

			// Try to inject via the query parameter
			_, err := client.SendMCPRequest("tools/call", map[string]any{
				"name": "query",
				"arguments": map[string]any{
					"query": payload,
				},
			})

			// We expect this to either fail gracefully or be sanitized
			// The exact behavior depends on the postgres MCP implementation
			// but it should NOT succeed in executing malicious SQL
			if err != nil {
			} else {
				t.Logf("SQL injection payload was accepted")
			}
		}
	})

	t.Run("HeaderInjectionAttempts", func(t *testing.T) {
		// Test:

		// Try to inject malicious headers
		maliciousHeaders := []string{
			"test-token\r\nX-Injected: malicious",
			"test-token\nSet-Cookie: session=hacked",
			"test-token\r\nLocation: http://evil.com",
			"test-token\x00\x0aX-Injected: malicious",
		}

		for _, maliciousAuth := range maliciousHeaders {
			// Testing header injection

			client := &http.Client{}
			req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
			req.Header.Set("Authorization", "Bearer "+maliciousAuth)
			req.Header.Set("Accept", "text/event-stream")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Check that no injected headers are reflected
			for headerName := range resp.Header {
				if strings.Contains(strings.ToLower(headerName), "injected") ||
					strings.Contains(strings.ToLower(headerName), "cookie") {
					t.Errorf("Possible header injection detected: %s", headerName)
				}
			}

			if resp.StatusCode != 401 {
				t.Errorf("Expected 401 for header injection attempt, got %d", resp.StatusCode)
			}
		}
	})

	t.Run("PathTraversalAttempts", func(t *testing.T) {
		// Test:

		pathTraversalAttempts := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			"....//....//....//etc/passwd",
			"/postgres/../../../etc/passwd",
		}

		for _, path := range pathTraversalAttempts {
			// Testing path traversal

			client := &http.Client{}
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:8080/%s", path), nil)
			req.Header.Set("Authorization", "Bearer test-token")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Should return 404 or 403, NOT 200 with sensitive content
			if resp.StatusCode == 200 {
				t.Errorf("Path traversal may have succeeded: %s returned 200", path)
			}
		}
	})

	t.Run("TokenReuse", func(t *testing.T) {
		// Test:

		// Test that the same token works consistently
		client1 := NewMCPSSEClient("http://localhost:8080")
		client1.token = "test-token"

		client2 := NewMCPSSEClient("http://localhost:8080")
		client2.token = "test-token"

		// Both should work with same token
		err1 := client1.ValidateBackendConnectivity()
		err2 := client2.ValidateBackendConnectivity()

		assert.NoError(t, err1, "Valid token should work for client1")
		assert.NoError(t, err2, "Valid token should work for client2")
	})

	t.Run("AuthenticationBypass", func(t *testing.T) {
		// Test:

		// Test case: token without Bearer prefix should be rejected
		t.Run("RejectsTokenWithoutBearer", func(t *testing.T) {
			client := &http.Client{}
			req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
			req.Header.Set("Authorization", "test-token") // Missing "Bearer " prefix
			req.Header.Set("Accept", "text/event-stream")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			resp.Body.Close()

			switch resp.StatusCode {
			case 200:
				t.Errorf("CRITICAL: Auth bypass! 'test-token' without Bearer returned 200")
			case 401:
			default:
				t.Logf("Unexpected status %d for malformed auth", resp.StatusCode)
			}
		})

		// Test various malformed auth headers
		malformedCases := []struct {
			name       string
			authHeader string
			shouldPass bool
		}{
			{"ValidBearer", "Bearer test-token", true},
			{"NoBearer", "test-token", false},
			{"WrongCase", "bearer test-token", false},
			{"ExtraSpaces", "Bearer  test-token", false},
			{"ExtraText", "Bearer test-token extra", false},
			{"BasicAuth", "Basic test-token", false},
		}

		for _, tc := range malformedCases {
			t.Run(tc.name, func(t *testing.T) {
				client := &http.Client{}
				req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
				req.Header.Set("Authorization", tc.authHeader)
				req.Header.Set("Accept", "text/event-stream")

				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				resp.Body.Close()

				if tc.shouldPass && resp.StatusCode != 200 {
					t.Errorf("Valid auth '%s' should return 200, got %d", tc.authHeader, resp.StatusCode)
				} else if !tc.shouldPass && resp.StatusCode != 401 {
					t.Errorf("Invalid auth '%s' should return 401, got %d", tc.authHeader, resp.StatusCode)
				}
			})
		}
	})

	t.Run("RateLimitingCheck", func(t *testing.T) {
		// Test:

		client := NewMCPSSEClient("http://localhost:8080")
		_ = client.Authenticate()

		successCount := 0
		errorCount := 0

		// Make rapid requests to see if there's any rate limiting
		for range 10 {
			err := client.ValidateBackendConnectivity()
			if err != nil {
				errorCount++
			} else {
				successCount++
			}
		}

		// Rapid requests completed - no rate limiting expected in this implementation
	})
}

// TestFailureScenarios validates error handling
func TestFailureScenarios(t *testing.T) {
	// Testing failure scenarios

	t.Run("FailsWithWrongAuth", func(t *testing.T) {
		// Database is already started by TestMain, just wait for readiness
		waitForDB(t)

		startMCPFront(t, "config/config.test.json")

		// Wait for server to be ready
		waitForMCPFront(t)

		// Test comprehensive token validation
		testCases := []struct {
			name     string
			token    string
			expected int
		}{
			{"ValidToken", "test-token", 200},
			{"EmptyToken", "", 401},
			{"WrongToken", "wrong-token", 401},
			{"LongToken", strings.Repeat("a", 1000), 401},
			{"SpecialChars", "test-token!@#$%^&*()", 401},
			{"UnicodeToken", "test-token-🔒", 401},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				client := &http.Client{}
				req, _ := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)

				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				req.Header.Set("Accept", "text/event-stream")

				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("Request failed: %v", err)
				}
				resp.Body.Close()

				assert.Equal(t, tc.expected, resp.StatusCode, "Token '%s' test failed", tc.name)
			})
		}
	})
}
