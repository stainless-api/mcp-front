package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

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

// FakeGitHubServer simulates GitHub's OAuth and API endpoints for integration testing.
type FakeGitHubServer struct {
	server *http.Server
	port   string
}

// NewFakeGitHubServer creates a new fake GitHub server.
// orgs controls what organizations the /user/orgs endpoint returns.
func NewFakeGitHubServer(port string, orgs []string) *FakeGitHubServer {
	mux := http.NewServeMux()

	mux.HandleFunc("/login/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, fmt.Sprintf("%s?code=github-test-code&state=%s", redirectURI, state), http.StatusFound)
	})

	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		if code != "github-test-code" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             "bad_verification_code",
				"error_description": "Invalid authorization code",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "github-test-token",
			"token_type":   "bearer",
			"scope":        "user:email,read:org",
		})
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         12345,
			"login":      "testuser",
			"email":      "test@test.com",
			"name":       "Test User",
			"avatar_url": "https://github.com/avatar.jpg",
		})
	})

	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"email": "test@test.com", "primary": true, "verified": true},
		})
	})

	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		orgList := make([]map[string]any, len(orgs))
		for i, org := range orgs {
			orgList[i] = map[string]any{"login": org}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(orgList)
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	return &FakeGitHubServer{
		server: server,
		port:   port,
	}
}

// Start starts the fake GitHub server
func (s *FakeGitHubServer) Start() error {
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

// Stop stops the fake GitHub server
func (s *FakeGitHubServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// FakeOIDCServer simulates a generic OIDC provider for integration testing.
// Used for both generic OIDC and Azure tests (Azure is OIDC-compliant).
type FakeOIDCServer struct {
	server *http.Server
	port   string
}

// NewFakeOIDCServer creates a new fake OIDC server.
func NewFakeOIDCServer(port string) *FakeOIDCServer {
	mux := http.NewServeMux()

	baseURL := "http://localhost:" + port

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 baseURL,
			"authorization_endpoint": baseURL + "/authorize",
			"token_endpoint":         baseURL + "/token",
			"userinfo_endpoint":      baseURL + "/userinfo",
		})
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		http.Redirect(w, r, fmt.Sprintf("%s?code=oidc-test-code&state=%s", redirectURI, state), http.StatusFound)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		if code != "oidc-test-code" {
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
			"access_token": "oidc-test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":            "oidc-12345",
			"email":          "test@oidc-test.com",
			"email_verified": true,
			"name":           "OIDC User",
		})
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	return &FakeOIDCServer{
		server: server,
		port:   port,
	}
}

// Start starts the fake OIDC server
func (s *FakeOIDCServer) Start() error {
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	return nil
}

// Stop stops the fake OIDC server
func (s *FakeOIDCServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}
