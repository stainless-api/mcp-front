package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/dgellow/mcp-front/internal/log"
)

// HTTPServer manages the HTTP server lifecycle
type HTTPServer struct {
	server *http.Server
}

// NewHTTPServer creates a new HTTP server with the given handler and address
func NewHTTPServer(handler http.Handler, addr string) *HTTPServer {
	return &HTTPServer{
		server: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
	}
}

// HealthHandler handles health check requests
type HealthHandler struct{}

// NewHealthHandler creates a new health handler
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// ServeHTTP implements http.Handler for health checks
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// Start starts the HTTP server
func (h *HTTPServer) Start() error {
	log.LogInfoWithFields("http", "HTTP server starting", map[string]any{
		"addr": h.server.Addr,
	})

	if err := h.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Stop gracefully stops the HTTP server
func (h *HTTPServer) Stop(ctx context.Context) error {
	log.LogInfoWithFields("http", "HTTP server stopping", map[string]any{
		"addr": h.server.Addr,
	})

	if err := h.server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	log.LogInfoWithFields("http", "HTTP server stopped", map[string]any{
		"addr": h.server.Addr,
	})
	return nil
}
