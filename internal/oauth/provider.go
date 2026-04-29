package oauth

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/stainless-api/mcp-front/internal/crypto"
	"github.com/stainless-api/mcp-front/internal/log"
	"github.com/stainless-api/mcp-front/internal/servicecontext"
)

const userContextKey contextKey = "user_email"

func GetUserFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(userContextKey).(string)
	return email, ok
}

func GetUserContextKey() contextKey {
	return userContextKey
}

func NewSessionEncryptor(encryptionKey []byte) (crypto.Encryptor, error) {
	sessionEncryptor, err := crypto.NewEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create session encryptor: %w", err)
	}
	log.Logf("Session encryptor initialized for browser SSO")
	return sessionEncryptor, nil
}

func GenerateJWTSecret(providedSecret string) ([]byte, error) {
	if providedSecret != "" {
		secret := []byte(providedSecret)
		if len(secret) < 32 {
			return nil, fmt.Errorf("JWT secret must be at least 32 bytes long for security, got %d bytes", len(secret))
		}
		return secret, nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	log.LogWarn("Generated random JWT secret. Set JWT_SECRET env var for persistent tokens across restarts")
	return secret, nil
}

// NewValidateTokenMiddleware tries to authenticate the request as an OAuth
// Bearer token. On success it sets the OAuth user-email context and continues.
// On any failure (missing header, wrong scheme, invalid signature, expired,
// wrong audience) it passes through unchanged — the downstream RequireAuth
// gate produces the 401 with the RFC 9728 Bearer challenge.
func NewValidateTokenMiddleware(authServer *AuthorizationServer, issuer string, acceptIssuerAudience bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// If service auth already authenticated this request, skip JWT
			// parsing — pure optimization, the gate would accept either way.
			if _, ok := servicecontext.GetAuthInfo(ctx); ok {
				next.ServeHTTP(w, r)
				return
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				next.ServeHTTP(w, r)
				return
			}
			parts := strings.Split(auth, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				next.ServeHTTP(w, r)
				return
			}

			claims, err := authServer.ValidateAccessToken(parts[1])
			if err != nil {
				log.LogTraceWithFields("oauth", "Token validation failed", map[string]any{"error": err.Error()})
				next.ServeHTTP(w, r)
				return
			}

			if err := ValidateAudienceForService(r.URL.Path, claims.Audience, issuer, acceptIssuerAudience); err != nil {
				log.LogErrorWithFields("oauth", "Audience validation failed", map[string]any{
					"path":     r.URL.Path,
					"audience": claims.Audience,
					"error":    err.Error(),
				})
				next.ServeHTTP(w, r)
				return
			}

			// Mark the context as OAuth-authenticated regardless of whether the
			// IDP populated an email — the gate's pass-through decision is "did
			// authentication succeed", not "do we have a user identity". In
			// practice mcp-front only issues tokens for identities that passed
			// AllowedDomains/AllowedOrgs at the OAuth flow, so claims.Identity.Email
			// is non-empty here, but we don't rely on that invariant for the gate.
			ctx = context.WithValue(ctx, userContextKey, claims.Identity.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ExtractServiceNameFromPath(requestPath string, issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}

	basePath := u.Path
	if basePath == "" {
		basePath = "/"
	}

	path := requestPath
	if basePath != "/" {
		if !strings.HasPrefix(path, basePath) {
			return ""
		}
		remainder := path[len(basePath):]
		if remainder != "" && !strings.HasPrefix(remainder, "/") {
			return ""
		}
		path = remainder
	}
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		return ""
	}

	return parts[0]
}
