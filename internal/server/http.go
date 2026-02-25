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

// Stop gracefully stops the HTTP server. It waits up to ctx's deadline for
// in-flight requests to finish, then force-closes any remaining connections
// (typically long-lived SSE streams) so handlers can exit via ctx.Done().
func (h *HTTPServer) Stop(ctx context.Context) error {
	log.LogInfoWithFields("http", "HTTP server stopping", map[string]any{
		"addr": h.server.Addr,
	})

	shutdownErr := h.server.Shutdown(ctx)
	// Force-close any connections still open after the graceful window
	// (e.g. SSE streams that never complete on their own).
	h.server.Close()

	if shutdownErr != nil && !errors.Is(shutdownErr, http.ErrServerClosed) {
		return shutdownErr
	}

	log.LogInfoWithFields("http", "HTTP server stopped", map[string]any{
		"addr": h.server.Addr,
	})
	return nil
}
