package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthEndpoint(t *testing.T) {
	handler := NewHealthHandler()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "ok", response["status"])
}

func TestOAuthEndpointsCORS(t *testing.T) {
	// Setup OAuth config
	oauthConfig := config.OAuthAuthConfig{
		Kind:               config.AuthKindOAuth,
		Issuer:             "https://test.example.com",
		GoogleClientID:     "test-client-id",
		GoogleClientSecret: config.Secret("test-client-secret"),
		GoogleRedirectURI:  "https://test.example.com/oauth/callback",
		JWTSecret:          config.Secret(strings.Repeat("a", 32)),
		EncryptionKey:      config.Secret(strings.Repeat("b", 32)),
		TokenTTL:           time.Hour,
		Storage:            "memory",
		AllowedOrigins:     []string{"http://localhost:6274"},
	}

	store := storage.NewMemoryStorage()
	jwtSecret, err := oauth.GenerateJWTSecret(string(oauthConfig.JWTSecret))
	require.NoError(t, err)
	oauthProvider, err := oauth.NewOAuthProvider(oauthConfig, store, jwtSecret)
	require.NoError(t, err)
	sessionEncryptor, err := oauth.NewSessionEncryptor([]byte(oauthConfig.EncryptionKey))
	require.NoError(t, err)
	serviceOAuthClient := auth.NewServiceOAuthClient(store, "https://test.example.com", []byte(strings.Repeat("k", 32)))

	authHandlers := NewAuthHandlers(
		oauthProvider,
		oauthConfig,
		store,
		sessionEncryptor,
		map[string]*config.MCPClientConfig{},
		serviceOAuthClient,
	)

	// Test endpoints that should have CORS headers
	endpoints := []struct {
		path   string
		method string
	}{
		{"/.well-known/oauth-authorization-server", "GET"},
		{"/.well-known/oauth-authorization-server", "OPTIONS"},
		{"/register", "POST"},
		{"/register", "OPTIONS"},
	}

	corsMiddleware := NewCORSMiddleware([]string{"http://localhost:6274"})

	for _, endpoint := range endpoints {
		t.Run(endpoint.method+" "+endpoint.path, func(t *testing.T) {
			var req *http.Request

			if endpoint.path == "/register" && endpoint.method == "POST" {
				requestBody := `{"redirect_uris": ["https://client.example.com/callback"], "scope": "read write"}`
				req = httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(requestBody))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(endpoint.method, endpoint.path, nil)
			}

			req.Header.Set("Origin", "http://localhost:6274")

			// For preflight requests, add required headers
			if endpoint.method == "OPTIONS" {
				req.Header.Set("Access-Control-Request-Method", "GET")
				req.Header.Set("Access-Control-Request-Headers", "authorization")
			}

			w := httptest.NewRecorder()

			// Create CORS-wrapped handler
			var handler http.Handler

			switch endpoint.path {
			case "/.well-known/oauth-authorization-server":
				handler = corsMiddleware(http.HandlerFunc(authHandlers.WellKnownHandler))
			case "/register":
				handler = corsMiddleware(http.HandlerFunc(authHandlers.RegisterHandler))
			default:
				t.Fatalf("Unknown endpoint: %s", endpoint.path)
			}

			handler.ServeHTTP(w, req)

			// Check CORS headers are present
			corsHeaders := map[string]string{
				"Access-Control-Allow-Origin":      "http://localhost:6274",
				"Access-Control-Allow-Methods":     "GET, POST, OPTIONS",
				"Access-Control-Allow-Headers":     "Content-Type, Authorization, Cache-Control, mcp-protocol-version",
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Max-Age":           "3600",
			}

			for header, expectedValue := range corsHeaders {
				actualValue := w.Header().Get(header)
				assert.Equal(t, expectedValue, actualValue, "Header %s", header)
			}

			// OPTIONS requests should return 200 OK
			if endpoint.method == "OPTIONS" {
				assert.Equal(t, http.StatusOK, w.Code, "OPTIONS should return 200")
			}
		})
	}
}
