package oauth

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/envutil"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauthsession"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

// userContextKey is the context key for user email
const userContextKey contextKey = "user_email"

// GetUserFromContext extracts user email from context
func GetUserFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(userContextKey).(string)
	return email, ok
}

// GetUserContextKey returns the context key for user email (for testing)
func GetUserContextKey() contextKey {
	return userContextKey
}

// NewOAuthProvider creates a new OAuth 2.1 provider with clean dependency injection
func NewOAuthProvider(oauthConfig config.OAuthAuthConfig, store storage.Storage, jwtSecret []byte) (fosite.OAuth2Provider, error) {
	// Use TTL duration from config
	tokenTTL := oauthConfig.TokenTTL
	if tokenTTL == 0 {
		tokenTTL = time.Hour // Default 1 hour
	}
	// Validate JWT secret length for HMAC-SHA512/256
	if len(jwtSecret) < 32 {
		return nil, fmt.Errorf("JWT secret must be at least 32 bytes long for security, got %d bytes", len(jwtSecret))
	}

	// Determine min parameter entropy based on environment
	minEntropy := 8 // Production default - enforce secure state parameters (8+ chars)
	log.Logf("OAuth provider initialization - MCP_FRONT_ENV=%s, isDevelopmentMode=%v", os.Getenv("MCP_FRONT_ENV"), envutil.IsDev())
	if envutil.IsDev() {
		minEntropy = 0 // Development mode - allow empty state parameters
		log.LogWarn("Development mode enabled - OAuth security checks relaxed (state parameter entropy: %d)", minEntropy)
	}

	// Configure fosite
	fositeConfig := &compose.Config{
		AccessTokenLifespan:            tokenTTL,
		RefreshTokenLifespan:           tokenTTL * 2,
		AuthorizeCodeLifespan:          10 * time.Minute,
		TokenURL:                       oauthConfig.Issuer + "/token",
		ScopeStrategy:                  fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		MinParameterEntropy:            minEntropy,
	}

	// Create provider using compose with specific factories
	provider := compose.Compose(
		fositeConfig,
		store,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(fositeConfig, jwtSecret, nil),
		},
		nil, // hasher
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	return provider, nil
}

// NewSessionEncryptor creates a new session encryptor for browser SSO
func NewSessionEncryptor(encryptionKey []byte) (crypto.Encryptor, error) {
	sessionEncryptor, err := crypto.NewEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create session encryptor: %w", err)
	}
	log.Logf("Session encryptor initialized for browser SSO")
	return sessionEncryptor, nil
}

// GenerateJWTSecret generates a secure JWT secret if none is provided
func GenerateJWTSecret(providedSecret string) ([]byte, error) {
	if providedSecret != "" {
		secret := []byte(providedSecret)
		// Validate JWT secret length for HMAC-SHA512/256
		if len(secret) < 32 {
			return nil, fmt.Errorf("JWT secret must be at least 32 bytes long for security, got %d bytes", len(secret))
		}
		return secret, nil
	}

	// Generate a secure random secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
	}
	log.LogWarn("Generated random JWT secret. Set JWT_SECRET env var for persistent tokens across restarts")
	return secret, nil
}

// NewValidateTokenMiddleware creates middleware that validates OAuth tokens using dependency injection
func NewValidateTokenMiddleware(provider fosite.OAuth2Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract token from Authorization header
			auth := r.Header.Get("Authorization")
			if auth == "" {
				http.Error(w, "Missing authorization header", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(auth, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			token := parts[1]

			// Validate token and extract session
			// IMPORTANT: Fosite's IntrospectToken behavior is non-intuitive:
			// - The session parameter passed to IntrospectToken is NOT populated with data
			// - This is documented fosite behavior, not a bug
			// - The actual session data must be retrieved from the returned AccessRequester
			// See: https://github.com/ory/fosite/issues/256
			session := &oauthsession.Session{DefaultSession: &fosite.DefaultSession{}}
			_, accessRequest, err := provider.IntrospectToken(ctx, token, fosite.AccessToken, session)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Get the actual session from the access request (not the input session parameter)
			// This is the correct way to retrieve session data after token introspection
			var userEmail string
			if accessRequest != nil {
				if reqSession, ok := accessRequest.GetSession().(*oauthsession.Session); ok {
					if reqSession.UserInfo.Email != "" {
						userEmail = reqSession.UserInfo.Email
					}
				}
			}

			// Pass user info through context
			if userEmail != "" {
				ctx = context.WithValue(ctx, userContextKey, userEmail)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}
