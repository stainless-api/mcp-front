package oauth

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgellow/mcp-front/internal/crypto"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
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

func NewValidateTokenMiddleware(authServer *AuthorizationServer, issuer string, acceptIssuerAudience bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			serviceName := ExtractServiceNameFromPath(r.URL.Path, issuer)
			metadataURI := ""
			if serviceName != "" {
				if uri, err := ServiceProtectedResourceMetadataURI(issuer, serviceName); err == nil {
					metadataURI = uri
				}
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				jsonwriter.WriteUnauthorizedRFC9728(w, "Missing authorization header", metadataURI)
				return
			}

			parts := strings.Split(auth, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				jsonwriter.WriteUnauthorizedRFC9728(w, "Invalid authorization header format", metadataURI)
				return
			}

			token := parts[1]

			claims, err := authServer.ValidateAccessToken(token)
			if err != nil {
				jsonwriter.WriteUnauthorizedRFC9728(w, "Invalid or expired token", metadataURI)
				return
			}

			if err := ValidateAudienceForService(r.URL.Path, claims.Audience, issuer, acceptIssuerAudience); err != nil {
				log.LogErrorWithFields("oauth", "Audience validation failed", map[string]any{
					"path":     r.URL.Path,
					"audience": claims.Audience,
					"error":    err.Error(),
				})
				jsonwriter.WriteUnauthorizedRFC9728(w, "Token audience does not match requested service", metadataURI)
				return
			}

			userEmail := claims.Identity.Email
			if userEmail != "" {
				ctx = context.WithValue(ctx, userContextKey, userEmail)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
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
