package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/servicecontext"
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

// TestServiceAuthMiddleware verifies the trier semantics of NewServiceAuthMiddleware:
// on a successful match it sets servicecontext and the wrapped handler runs;
// on any other input it passes through unchanged (no auth context, no 401).
// The 401 is the responsibility of the downstream RequireAuth gate, exercised
// separately in TestRequireAuthMiddleware.
func TestServiceAuthMiddleware(t *testing.T) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	const serverName = "Postgres" // mixed case to verify lowercase canonicalization
	serviceAuths := []config.ServiceAuth{
		{
			Type:      config.ServiceAuthTypeBearer,
			Name:      "ci",
			Tokens:    []string{"valid-token-1", "valid-token-2"},
			UserToken: config.Secret("bearer-user-token"),
		},
		{
			Type:           config.ServiceAuthTypeBasic,
			Name:           "user",
			Username:       "user",
			HashedPassword: config.Secret(hashedPassword),
			UserToken:      config.Secret("basic-user-token"),
		},
	}

	const (
		bearerIdentity = "postgres.ci@" + ServiceAuthDomain
		basicIdentity  = "postgres.user@" + ServiceAuthDomain
	)

	tests := []struct {
		name           string
		authHeader     string
		wantAuthInfo   bool
		wantAuthInfoEq servicecontext.Info
		wantOAuthEmail string
	}{
		{
			name:           "valid bearer token",
			authHeader:     "Bearer valid-token-1",
			wantAuthInfo:   true,
			wantAuthInfoEq: servicecontext.Info{ServiceName: bearerIdentity, UserToken: "bearer-user-token"},
			wantOAuthEmail: bearerIdentity,
		},
		{
			name:           "another valid bearer token",
			authHeader:     "Bearer valid-token-2",
			wantAuthInfo:   true,
			wantAuthInfoEq: servicecontext.Info{ServiceName: bearerIdentity, UserToken: "bearer-user-token"},
			wantOAuthEmail: bearerIdentity,
		},
		{
			name:           "valid basic auth",
			authHeader:     "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password123")),
			wantAuthInfo:   true,
			wantAuthInfoEq: servicecontext.Info{ServiceName: basicIdentity, UserToken: "basic-user-token"},
			wantOAuthEmail: basicIdentity,
		},
		{name: "invalid bearer token passes through", authHeader: "Bearer invalid-token"},
		{name: "invalid basic password passes through", authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("user:wrongpassword"))},
		{name: "unknown basic user passes through", authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("wronguser:password123"))},
		{name: "malformed basic header passes through", authHeader: "Basic malformed"},
		{name: "missing colon in basic passes through", authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("usernopassword"))},
		{name: "no auth header passes through", authHeader: ""},
		{name: "unsupported scheme passes through", authHeader: "Unsupported scheme"},
		{name: "empty bearer token passes through", authHeader: "Bearer "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAuthInfo servicecontext.Info
			var gotHasAuthInfo bool
			var gotOAuthEmail string
			var handlerCalled bool

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				gotAuthInfo, gotHasAuthInfo = servicecontext.GetAuthInfo(r.Context())
				gotOAuthEmail, _ = oauth.GetUserFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rr := httptest.NewRecorder()
			NewServiceAuthMiddleware(serverName, serviceAuths)(handler).ServeHTTP(rr, req)

			assert.True(t, handlerCalled, "trier must always pass through to next handler")
			assert.Equal(t, http.StatusOK, rr.Code, "trier must not write a status itself")
			assert.Equal(t, tt.wantAuthInfo, gotHasAuthInfo)
			if tt.wantAuthInfo {
				assert.Equal(t, tt.wantAuthInfoEq, gotAuthInfo)
				assert.Equal(t, tt.wantOAuthEmail, gotOAuthEmail, "should set oauth context to synthetic email")
			} else {
				assert.Empty(t, gotOAuthEmail, "no auth means no oauth context")
			}
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"), "trier must not set WWW-Authenticate")
		})
	}
}

// TestServiceAuthMiddleware_BasicTimingEqualized verifies that Basic auth
// always runs bcrypt regardless of whether the username is configured, so the
// response timing does not leak which usernames exist.
//
// We don't measure absolute timing (too noisy in CI) — instead we measure the
// timing GAP between known-user and unknown-user requests over many trials.
// With the dummy-hash defense, both paths run one bcrypt; the median timing
// gap should be a tiny fraction of a single bcrypt call. Without the defense,
// the gap would be on the order of one bcrypt call (~tens of milliseconds at
// DefaultCost).
func TestServiceAuthMiddleware_BasicTimingEqualized(t *testing.T) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	mw := NewServiceAuthMiddleware("test-server", []config.ServiceAuth{{
		Type:           config.ServiceAuthTypeBasic,
		Name:           "alice",
		Username:       "alice",
		HashedPassword: config.Secret(hashedPassword),
	}})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	timeRequest := func(authHeader string) time.Duration {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", authHeader)
		rr := httptest.NewRecorder()
		start := time.Now()
		handler.ServeHTTP(rr, req)
		return time.Since(start)
	}

	const trials = 5
	known := make([]time.Duration, trials)
	unknown := make([]time.Duration, trials)
	for i := range trials {
		known[i] = timeRequest("Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrongpass")))
		unknown[i] = timeRequest("Basic " + base64.StdEncoding.EncodeToString([]byte("nobody:wrongpass")))
	}

	// Take medians to suppress GC/scheduler noise.
	median := func(ds []time.Duration) time.Duration {
		sorted := slices.Clone(ds)
		slices.Sort(sorted)
		return sorted[len(sorted)/2]
	}
	knownMed := median(known)
	unknownMed := median(unknown)
	gap := knownMed - unknownMed
	if gap < 0 {
		gap = -gap
	}

	// A single bcrypt at DefaultCost (10) takes ~50-100ms on typical hardware.
	// If the dummy-hash defense were missing, unknown would skip bcrypt entirely
	// and the gap would be roughly equal to knownMed. We assert the gap is well
	// under half of knownMed — generous to absorb CI noise but tight enough to
	// catch a regression that drops the dummy-hash call.
	assert.Less(t, gap, knownMed/2,
		"timing gap %v between known-user and unknown-user must be << bcrypt cost (known median %v, unknown median %v) — dummy-hash equalization regressed?",
		gap, knownMed, unknownMed)
}
