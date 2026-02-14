package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/cookie"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/idp"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/servicecontext"
	"github.com/dgellow/mcp-front/internal/session"
	"golang.org/x/crypto/bcrypt"
)

// MiddlewareFunc is a function that wraps an http.Handler
type MiddlewareFunc func(http.Handler) http.Handler

// ChainMiddleware chains multiple middleware functions
func ChainMiddleware(h http.Handler, middlewares ...MiddlewareFunc) http.Handler {
	for _, mw := range middlewares {
		h = mw(h)
	}
	return h
}

// NewCORSMiddleware adds CORS headers to responses
func NewCORSMiddleware(allowedOrigins []string) MiddlewareFunc {
	// Build a map for faster lookup
	allowedMap := make(map[string]bool)
	for _, origin := range allowedOrigins {
		allowedMap[origin] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Only set CORS headers if origin is allowed
			if origin != "" && allowedMap[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			} else if len(allowedOrigins) == 0 {
				// If no allowed origins configured, allow all (development mode)
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
			// If origin not allowed, don't set Access-Control-Allow-Origin header

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Cache-Control, mcp-protocol-version")
			w.Header().Set("Access-Control-Max-Age", "3600")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// responseWriterDelegator wraps http.ResponseWriter to capture status and bytes written
// while properly delegating all optional interfaces through Unwrap
type responseWriterDelegator struct {
	http.ResponseWriter
	status      int
	written     int
	wroteHeader bool
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriterDelegator {
	return &responseWriterDelegator{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

func (r *responseWriterDelegator) Status() int {
	return r.status
}

func (r *responseWriterDelegator) BytesWritten() int {
	return r.written
}

func (r *responseWriterDelegator) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseWriterDelegator) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += n
	return n, err
}

// Unwrap returns the underlying ResponseWriter for interface detection
// This allows Go 1.20+ to automatically detect interfaces like http.Flusher
// when used with http.ResponseController
func (r *responseWriterDelegator) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Flush implements http.Flusher
func (r *responseWriterDelegator) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Verify interfaces
var _ http.ResponseWriter = (*responseWriterDelegator)(nil)
var _ http.Flusher = (*responseWriterDelegator)(nil)

// loggerMiddleware adds request/response logging
func NewLoggerMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := wrapResponseWriter(w)

			next.ServeHTTP(wrapped, r)

			// Log request with response details
			fields := map[string]any{
				"method":      r.Method,
				"path":        r.URL.Path,
				"status":      wrapped.Status(),
				"duration_ms": time.Since(start).Milliseconds(),
				"bytes":       wrapped.BytesWritten(),
				"remote_addr": r.RemoteAddr,
			}

			// Add query string if present
			if r.URL.RawQuery != "" {
				fields["query"] = r.URL.RawQuery
			}

			log.LogInfoWithFields(prefix, "request", fields)
		})
	}
}

// NewRecoverMiddleware recovers from panics
func NewRecoverMiddleware(prefix string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					log.Logf("<%s> Recovered from panic: %v", prefix, err)
					jsonwriter.WriteInternalServerError(w, "Internal Server Error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// newServiceAuthMiddleware creates middleware for service-to-service authentication
func newServiceAuthMiddleware(serviceAuths []config.ServiceAuth) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check if user context is already set — OAuth succeeded, no need for further auth
			if userEmail, ok := oauth.GetUserFromContext(ctx); ok && userEmail != "" {
				log.LogTraceWithFields("service_auth", "Skipping service auth, user already authenticated via OAuth", map[string]any{
					"user": userEmail,
				})
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				log.LogTraceWithFields("service_auth", "Service auth failed: missing Authorization header", nil)
				jsonwriter.WriteUnauthorized(w, "Unauthorized")
				return
			}

			if strings.HasPrefix(authHeader, "Bearer ") {
				token := authHeader[7:]
				log.LogTraceWithFields("service_auth", "Attempting bearer token service auth", nil)
				for _, serviceAuth := range serviceAuths {
					if serviceAuth.Type != config.ServiceAuthTypeBearer {
						continue
					}

					if slices.Contains(serviceAuth.Tokens, token) {
						// Auth succeeded
						log.LogTraceWithFields("service_auth", "Bearer token service auth successful", map[string]any{
							"service_name": "service",
						})
						ctx := servicecontext.WithAuthInfo(r.Context(), "service", string(serviceAuth.UserToken))
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
				log.LogTraceWithFields("service_auth", "Bearer token service auth failed: invalid token", nil)
			}

			if strings.HasPrefix(authHeader, "Basic ") {
				encoded := authHeader[6:]
				log.LogTraceWithFields("service_auth", "Attempting basic service auth", nil)
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					log.LogTraceWithFields("service_auth", "Basic service auth failed: invalid base64 encoding", map[string]any{
						"error": err.Error(),
					})
					w.Header().Set("WWW-Authenticate", `Basic realm="mcp-front"`)
					jsonwriter.WriteUnauthorized(w, "Unauthorized")
					return
				}

				credentials := string(decoded)
				colonIdx := strings.IndexByte(credentials, ':')
				if colonIdx == -1 {
					log.LogTraceWithFields("service_auth", "Basic service auth failed: malformed credentials", nil)
					w.Header().Set("WWW-Authenticate", `Basic realm="mcp-front"`)
					jsonwriter.WriteUnauthorized(w, "Unauthorized")
					return
				}

				username := credentials[:colonIdx]
				password := credentials[colonIdx+1:]

				for _, serviceAuth := range serviceAuths {
					if serviceAuth.Type != config.ServiceAuthTypeBasic {
						continue
					}

					if username == serviceAuth.Username {
						if err := bcrypt.CompareHashAndPassword([]byte(string(serviceAuth.HashedPassword)), []byte(password)); err == nil {
							// Auth succeeded
							log.LogTraceWithFields("service_auth", "Basic service auth successful", map[string]any{
								"username": username,
							})
							ctx := servicecontext.WithAuthInfo(r.Context(), serviceAuth.Username, string(serviceAuth.UserToken))
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						}
					}
				}
				log.LogTraceWithFields("service_auth", "Basic service auth failed: invalid username or password", nil)
			}

			jsonwriter.WriteUnauthorized(w, "Unauthorized")
		})
	}
}

// NewBrowserSSOMiddleware creates middleware for browser-based SSO authentication
func NewBrowserSSOMiddleware(authConfig config.OAuthAuthConfig, idpProvider idp.Provider, sessionEncryptor crypto.Encryptor, browserStateToken *crypto.TokenSigner) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for session cookie
			sessionValue, err := cookie.GetSession(r)
			if err != nil {
				// No cookie, redirect directly to OAuth
				state := generateBrowserState(browserStateToken, r.URL.String())
				if state == "" {
					jsonwriter.WriteInternalServerError(w, "Failed to generate authentication state")
					return
				}
				authURL := idpProvider.AuthURL(state)
				http.Redirect(w, r, authURL, http.StatusFound)
				return
			}

			// Decrypt cookie
			decrypted, err := sessionEncryptor.Decrypt(sessionValue)
			if err != nil {
				// Invalid cookie, redirect to OAuth
				log.LogDebug("Invalid session cookie: %v", err)
				cookie.ClearSession(w) // Clear bad cookie
				state := generateBrowserState(browserStateToken, r.URL.String())
				authURL := idpProvider.AuthURL(state)
				http.Redirect(w, r, authURL, http.StatusFound)
				return
			}

			// Parse session data
			var sessionData session.BrowserCookie
			if err := json.NewDecoder(strings.NewReader(decrypted)).Decode(&sessionData); err != nil {
				// Invalid format
				cookie.ClearSession(w)
				jsonwriter.WriteUnauthorized(w, "Invalid session")
				return
			}

			// Check expiration
			if sessionData.IsExpired() {
				log.LogDebug("Session expired for user %s", sessionData.Email)
				cookie.ClearSession(w)
				// Redirect directly to OAuth
				state := generateBrowserState(browserStateToken, r.URL.String())
				if state == "" {
					jsonwriter.WriteInternalServerError(w, "Failed to generate authentication state")
					return
				}
				authURL := idpProvider.AuthURL(state)
				http.Redirect(w, r, authURL, http.StatusFound)
				return
			}

			// Valid session, set user in context
			// Use oauth.WithUserContext to set user for OAuth-protected endpoints
			// (token management, service selection page, etc.)
			ctx := context.WithValue(r.Context(), oauth.GetUserContextKey(), sessionData.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// generateBrowserState creates a secure state parameter for browser SSO
func generateBrowserState(browserStateToken *crypto.TokenSigner, returnURL string) string {
	nonce, err := crypto.GenerateSecureToken()
	if err != nil {
		log.LogError("Failed to generate browser state nonce: %v", err)
		return ""
	}

	state := session.AuthorizationState{
		Nonce:     nonce,
		ReturnURL: returnURL,
	}

	token, err := browserStateToken.Sign(state)
	if err != nil {
		log.LogError("Failed to sign browser state: %v", err)
		return ""
	}
	return "browser:" + token
}

// NewServiceAuthMiddleware creates middleware for service-to-service authentication
func NewServiceAuthMiddleware(serviceAuths []config.ServiceAuth) MiddlewareFunc {
	return newServiceAuthMiddleware(serviceAuths)
}
