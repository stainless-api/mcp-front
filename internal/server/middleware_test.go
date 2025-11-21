package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/servicecontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestCorsMiddleware(t *testing.T) {
	tests := []struct {
		name              string
		allowedOrigins    []string
		requestOrigin     string
		expectAllowOrigin string
		expectCredentials bool
		expectWildcard    bool
	}{
		{
			name:              "allowed origin",
			allowedOrigins:    []string{"https://claude.ai", "https://example.com"},
			requestOrigin:     "https://claude.ai",
			expectAllowOrigin: "https://claude.ai",
			expectCredentials: true,
		},
		{
			name:              "disallowed origin",
			allowedOrigins:    []string{"https://claude.ai", "https://example.com"},
			requestOrigin:     "https://evil.com",
			expectAllowOrigin: "",
			expectCredentials: false,
		},
		{
			name:              "no origin header",
			allowedOrigins:    []string{"https://claude.ai"},
			requestOrigin:     "",
			expectAllowOrigin: "",
			expectCredentials: false,
		},
		{
			name:              "empty allowed origins with origin",
			allowedOrigins:    []string{},
			requestOrigin:     "https://claude.ai",
			expectAllowOrigin: "*",
			expectWildcard:    true,
		},
		{
			name:              "empty allowed origins no origin",
			allowedOrigins:    []string{},
			requestOrigin:     "",
			expectAllowOrigin: "*",
			expectWildcard:    true,
		},
		{
			name:              "preflight request",
			allowedOrigins:    []string{"https://claude.ai"},
			requestOrigin:     "https://claude.ai",
			expectAllowOrigin: "https://claude.ai",
			expectCredentials: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that just returns 200 OK
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with CORS middleware
			corsHandler := NewCORSMiddleware(tt.allowedOrigins)(handler)

			// Create request
			method := "GET"
			if tt.name == "preflight request" {
				method = "OPTIONS"
			}
			req := httptest.NewRequest(method, "/test", nil)
			if tt.requestOrigin != "" {
				req.Header.Set("Origin", tt.requestOrigin)
			}

			// Execute request
			rr := httptest.NewRecorder()
			corsHandler.ServeHTTP(rr, req)

			// Check Access-Control-Allow-Origin header
			if tt.expectAllowOrigin != "" {
				assert.Equal(t, tt.expectAllowOrigin, rr.Header().Get("Access-Control-Allow-Origin"))
			} else {
				assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
			}

			// Check Access-Control-Allow-Credentials header
			if tt.expectCredentials {
				assert.Equal(t, "true", rr.Header().Get("Access-Control-Allow-Credentials"))
			} else if !tt.expectWildcard {
				// When using wildcard (*), credentials header should not be set
				assert.Empty(t, rr.Header().Get("Access-Control-Allow-Credentials"))
			}

			// Check that standard CORS headers are always set
			assert.Equal(t, "GET, POST, OPTIONS", rr.Header().Get("Access-Control-Allow-Methods"))
			assert.Equal(t, "Content-Type, Authorization, Cache-Control, mcp-protocol-version", rr.Header().Get("Access-Control-Allow-Headers"))
			assert.Equal(t, "3600", rr.Header().Get("Access-Control-Max-Age"))

			// For OPTIONS requests, check status code
			if method == "OPTIONS" {
				assert.Equal(t, http.StatusOK, rr.Code)
			}
		})
	}
}

func TestCorsMiddleware_CaseSensitivity(t *testing.T) {
	// Test that origin matching is case-sensitive
	allowedOrigins := []string{"https://Claude.AI"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := NewCORSMiddleware(allowedOrigins)(handler)

	// Test with different case
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://claude.ai")

	rr := httptest.NewRecorder()
	corsHandler.ServeHTTP(rr, req)

	// Should not match due to case difference
	assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
}

func TestCorsMiddleware_MultipleOrigins(t *testing.T) {
	// Test with multiple allowed origins
	allowedOrigins := []string{
		"https://claude.ai",
		"https://app.claude.ai",
		"https://dev.claude.ai",
		"https://staging.claude.ai",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	corsHandler := NewCORSMiddleware(allowedOrigins)(handler)

	// Test each allowed origin
	for _, origin := range allowedOrigins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", origin)

			rr := httptest.NewRecorder()
			corsHandler.ServeHTTP(rr, req)

			assert.Equal(t, origin, rr.Header().Get("Access-Control-Allow-Origin"))
			assert.Equal(t, "true", rr.Header().Get("Access-Control-Allow-Credentials"))
		})
	}
}

func TestServiceAuthMiddleware(t *testing.T) {
	// Create a hashed password for basic auth tests
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	serviceAuths := []config.ServiceAuth{
		{
			Type:   config.ServiceAuthTypeBearer,
			Tokens: []string{"valid-token-1", "valid-token-2"},
		},
		{
			Type:           config.ServiceAuthTypeBasic,
			Username:       "user",
			HashedPassword: config.Secret(hashedPassword),
		},
	}

	tests := []struct {
		name           string
		authHeader     string
		expectStatus   int
		expectUsername string // For context check
	}{
		{
			name:         "valid bearer token",
			authHeader:   "Bearer valid-token-1",
			expectStatus: http.StatusOK,
		},
		{
			name:         "another valid bearer token",
			authHeader:   "Bearer valid-token-2",
			expectStatus: http.StatusOK,
		},
		{
			name:         "invalid bearer token",
			authHeader:   "Bearer invalid-token",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "valid basic auth",
			authHeader:   "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password123")),
			expectStatus: http.StatusOK,
		},
		{
			name:         "invalid basic auth password",
			authHeader:   "Basic " + base64.StdEncoding.EncodeToString([]byte("user:wrongpassword")),
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "invalid basic auth user",
			authHeader:   "Basic " + base64.StdEncoding.EncodeToString([]byte("wronguser:password123")),
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "malformed basic auth header",
			authHeader:   "Basic malformed",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "no auth header",
			authHeader:   "",
			expectStatus: http.StatusUnauthorized,
		},
		{
			name:         "unsupported auth scheme",
			authHeader:   "Unsupported scheme",
			expectStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with the service auth middleware
			authHandler := newServiceAuthMiddleware(serviceAuths)(handler)

			// Create request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Execute request
			rr := httptest.NewRecorder()
			authHandler.ServeHTTP(rr, req)

			// Check status code
			assert.Equal(t, tt.expectStatus, rr.Code)
		})
	}
}

func TestServiceAuthMiddleware_Context(t *testing.T) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	serviceAuths := []config.ServiceAuth{
		{
			Type:      config.ServiceAuthTypeBearer,
			Tokens:    []string{"valid-token"},
			UserToken: config.Secret("bearer-user-token"),
		},
		{
			Type:           config.ServiceAuthTypeBasic,
			Username:       "user",
			HashedPassword: config.Secret(hashedPassword),
			UserToken:      config.Secret("basic-user-token"),
		},
	}

	tests := []struct {
		name              string
		authHeader        string
		expectStatus      int
		expectServiceAuth bool
		expectAuthInfo    servicecontext.Info
	}{
		{
			name:              "bearer token sets context",
			authHeader:        "Bearer valid-token",
			expectStatus:      http.StatusOK,
			expectServiceAuth: true,
			expectAuthInfo: servicecontext.Info{
				ServiceName: "service",
				UserToken:   "bearer-user-token",
			},
		},
		{
			name:              "basic auth sets context",
			authHeader:        "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password123")),
			expectStatus:      http.StatusOK,
			expectServiceAuth: true,
			expectAuthInfo: servicecontext.Info{
				ServiceName: "user",
				UserToken:   "basic-user-token",
			},
		},
		{
			name:              "invalid auth does not set context",
			authHeader:        "Bearer invalid-token",
			expectStatus:      http.StatusUnauthorized,
			expectServiceAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var actualAuthInfo servicecontext.Info
			var hasAuthInfo bool

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actualAuthInfo, hasAuthInfo = servicecontext.GetAuthInfo(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			authHandler := newServiceAuthMiddleware(serviceAuths)(handler)
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.authHeader)
			rr := httptest.NewRecorder()
			authHandler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectStatus, rr.Code)
			assert.Equal(t, tt.expectServiceAuth, hasAuthInfo)
			if tt.expectServiceAuth {
				assert.Equal(t, tt.expectAuthInfo, actualAuthInfo)
			}
		})
	}
}
