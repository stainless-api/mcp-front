package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/stainless-api/mcp-front/internal/config"
	"github.com/stainless-api/mcp-front/internal/cookie"
	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/idp"
	jsonwriter "github.com/stainless-api/mcp-front/internal/json"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/servicecontext"
	"github.com/stainless-api/mcp-front/internal/session"
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

// ServiceAuthDomain re-exports servicecontext.IdentityDomain for callers
// that already use the server package.
const ServiceAuthDomain = servicecontext.IdentityDomain

// NewServiceAuthMiddleware tries to authenticate against serviceAuths. On
// success it sets both oauth.userContextKey (with synthetic email
// `<server>.<name>@serviceauth.mcpfront.alt`) and servicecontext.WithAuthInfo
// (carrying the configured userToken), then continues. On any failure it
// passes through — the RequireAuth gate produces the 401.
//
// Basic auth runs bcrypt against a dummy hash on no-match to equalize timing
// against unknown usernames.
func NewServiceAuthMiddleware(serverName string, serviceAuths []config.ServiceAuth) MiddlewareFunc {
	dummyBasicHash, err := bcrypt.GenerateFromPassword([]byte("mcp-front-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("service auth: failed to generate dummy bcrypt hash: %v", err))
	}

	identityPrefix := strings.ToLower(serverName) + "."
	authenticated := func(r *http.Request, entry *config.ServiceAuth) *http.Request {
		identity := identityPrefix + entry.Name + "@" + ServiceAuthDomain
		ctx := context.WithValue(r.Context(), oauth.GetUserContextKey(), identity)
		ctx = servicecontext.WithAuthInfo(ctx, identity, string(entry.UserToken))
		return r.WithContext(ctx)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				next.ServeHTTP(w, r)
				return
			}

			if token, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
				log.LogTraceWithFields("service_auth", "Attempting bearer token service auth", nil)
				for i := range serviceAuths {
					sa := &serviceAuths[i]
					if sa.Type != config.ServiceAuthTypeBearer {
						continue
					}
					if slices.Contains(sa.Tokens, token) {
						log.LogTraceWithFields("service_auth", "Bearer token service auth successful", map[string]any{"name": sa.Name})
						next.ServeHTTP(w, authenticated(r, sa))
						return
					}
				}
				log.LogTraceWithFields("service_auth", "Bearer token service auth: no match", nil)
				next.ServeHTTP(w, r)
				return
			}

			if encoded, ok := strings.CutPrefix(authHeader, "Basic "); ok {
				log.LogTraceWithFields("service_auth", "Attempting basic service auth", nil)
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					log.LogTraceWithFields("service_auth", "Basic service auth: invalid base64", map[string]any{"error": err.Error()})
					next.ServeHTTP(w, r)
					return
				}
				credentials := string(decoded)
				colonIdx := strings.IndexByte(credentials, ':')
				if colonIdx == -1 {
					log.LogTraceWithFields("service_auth", "Basic service auth: malformed credentials", nil)
					next.ServeHTTP(w, r)
					return
				}
				username := credentials[:colonIdx]
				password := credentials[colonIdx+1:]

				var matched *config.ServiceAuth
				for i := range serviceAuths {
					sa := &serviceAuths[i]
					if sa.Type != config.ServiceAuthTypeBasic {
						continue
					}
					if username == sa.Username {
						matched = sa
						break
					}
				}
				hashToCompare := dummyBasicHash
				if matched != nil {
					hashToCompare = []byte(string(matched.HashedPassword))
				}
				bcryptErr := bcrypt.CompareHashAndPassword(hashToCompare, []byte(password))
				if matched != nil && bcryptErr == nil {
					log.LogTraceWithFields("service_auth", "Basic service auth successful", map[string]any{"name": matched.Name})
					next.ServeHTTP(w, authenticated(r, matched))
					return
				}
				log.LogTraceWithFields("service_auth", "Basic service auth: no match", nil)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// NewRequireAuthMiddleware is the policy gate at the end of the auth chain. It
// passes through requests that any upstream trier authenticated (OAuth user or
// service auth info), and produces the 401 + WWW-Authenticate response for
// everything else. The shape of the challenge depends on the deployment:
//   - oauthEnabled: RFC 9728 Bearer challenge with the per-service
//     resource_metadata URI derived from the request path
//   - service-auth-only: Basic realm="mcp-front"
func NewRequireAuthMiddleware(oauthEnabled bool, issuer string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// Either authenticator marks success by setting its context key.
			// We check presence (ok), not value: an OAuth token with an empty
			// email claim is still a successfully-validated token and should
			// pass — the rejection of empty-email identities happens earlier
			// in the OAuth flow, not at the per-request gate.
			if _, ok := oauth.GetUserFromContext(ctx); ok {
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := servicecontext.GetAuthInfo(ctx); ok {
				next.ServeHTTP(w, r)
				return
			}

			if !oauthEnabled {
				w.Header().Set("WWW-Authenticate", `Basic realm="mcp-front"`)
				jsonwriter.WriteUnauthorized(w, "Unauthorized")
				return
			}

			metadataURI := ""
			if serviceName := oauth.ExtractServiceNameFromPath(r.URL.Path, issuer); serviceName != "" {
				if uri, err := oauth.ServiceProtectedResourceMetadataURI(issuer, serviceName); err == nil {
					metadataURI = uri
				}
			}
			jsonwriter.WriteUnauthorizedRFC9728(w, "Missing or invalid credentials", metadataURI)
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
				log.LogDebug("Invalid session format: %v", err)
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
