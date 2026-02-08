package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stainless-api/stainless-proxy/internal/config"
	"github.com/stainless-api/stainless-proxy/internal/keystore"
	"github.com/stainless-api/stainless-proxy/internal/proxy"
	"github.com/stainless-api/stainless-proxy/internal/revocation"
)

type Server struct {
	httpServer *http.Server
	denyList   *revocation.DenyList
}

func New(cfg *config.Config, ks *keystore.KeyStore, p *proxy.Proxy, dl *revocation.DenyList) *Server {
	mux := http.NewServeMux()
	handlers := NewHandlers(ks, dl)

	mux.HandleFunc("GET /.well-known/jwks.json", handlers.JWKS)
	mux.HandleFunc("GET /health", handlers.Health)
	mux.Handle("POST /revoke", ChainMiddleware(
		http.HandlerFunc(handlers.Revoke),
		RecoverMiddleware,
		LoggerMiddleware,
	))

	if cfg.MintEnabled {
		mintHandler := ChainMiddleware(
			http.HandlerFunc(handlers.Mint),
			MintAuthMiddleware(cfg.MintSecret),
			RecoverMiddleware,
			LoggerMiddleware,
		)
		mux.Handle("POST /mint", mintHandler)
		slog.Info("mint endpoint enabled")
	}

	// All other paths go to the proxy
	mux.Handle("/", ChainMiddleware(
		p,
		RecoverMiddleware,
		LoggerMiddleware,
	))

	return &Server{
		httpServer: &http.Server{
			Addr:    cfg.Addr,
			Handler: mux,
		},
		denyList: dl,
	}
}

func (s *Server) Run(ctx context.Context) error {
	s.denyList.StartCleanup(ctx, 5*time.Minute)

	errChan := make(chan error, 1)
	go func() {
		slog.Info("starting server", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		slog.Info("received signal", "signal", sig)
	case err := <-errChan:
		return err
	case <-ctx.Done():
		slog.Info("context cancelled")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(shutdownCtx)
}
