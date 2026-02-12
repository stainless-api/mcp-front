package server

import (
	"context"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
)

// UserTokenService handles user token retrieval and OAuth refresh
type UserTokenService struct {
	storage            storage.Storage
	serviceOAuthClient *auth.ServiceOAuthClient
}

// NewUserTokenService creates a new user token service
func NewUserTokenService(storage storage.Storage, serviceOAuthClient *auth.ServiceOAuthClient) *UserTokenService {
	return &UserTokenService{
		storage:            storage,
		serviceOAuthClient: serviceOAuthClient,
	}
}

// GetUserToken retrieves and formats a user token for a service, handling OAuth refresh.
//
// Token refresh strategy: Optimistic continuation on failure.
// If refresh fails, we log a warning and continue with the current token. The external
// service will reject the expired token with 401, giving the user a clear error.
// This is acceptable because: (1) refresh failures are rare (network issues, revoked
// tokens), and (2) forcing users to re-auth is better than silently hiding auth issues.
func (uts *UserTokenService) GetUserToken(ctx context.Context, userEmail, serviceName string, serviceConfig *config.MCPClientConfig) (string, error) {
	storedToken, err := uts.storage.GetUserToken(ctx, userEmail, serviceName)
	if err != nil {
		return "", err
	}

	switch storedToken.Type {
	case storage.TokenTypeManual:
		// Token is already in storedToken.Value, formatUserToken will handle it
		break
	case storage.TokenTypeOAuth:
		if storedToken.OAuthData != nil && uts.serviceOAuthClient != nil {
			if err := uts.serviceOAuthClient.RefreshToken(ctx, userEmail, serviceName, serviceConfig); err != nil {
				log.LogWarnWithFields("user_token", "Failed to refresh OAuth token", map[string]any{
					"service": serviceName,
					"user":    userEmail,
					"error":   err.Error(),
				})
				// Continue with current token - the service will handle auth failure
			} else {
				// Re-fetch the updated token after refresh
				refreshedToken, err := uts.storage.GetUserToken(ctx, userEmail, serviceName)
				if err != nil {
					log.LogErrorWithFields("user_token", "Failed to fetch token after successful refresh", map[string]any{
						"service": serviceName,
						"user":    userEmail,
						"error":   err.Error(),
					})
					// Continue with original token - the service will handle auth failure
				} else {
					storedToken = refreshedToken
					var expiresAt time.Time
					if refreshedToken.OAuthData != nil {
						expiresAt = refreshedToken.OAuthData.ExpiresAt
					}
					log.LogInfoWithFields("user_token", "OAuth token refreshed and updated", map[string]any{
						"service":   serviceName,
						"user":      userEmail,
						"expiresAt": expiresAt,
					})
				}
			}
		}
	}

	return formatUserToken(storedToken, serviceConfig.UserAuthentication), nil
}

// formatUserToken formats a stored token according to the user authentication configuration
func formatUserToken(storedToken *storage.StoredToken, auth *config.UserAuthentication) string {
	if storedToken == nil {
		return ""
	}

	if storedToken.Type == storage.TokenTypeOAuth && storedToken.OAuthData != nil {
		token := storedToken.OAuthData.AccessToken
		if auth.TokenFormat != "" && auth.TokenFormat != "{{token}}" {
			return strings.ReplaceAll(auth.TokenFormat, "{{token}}", token)
		}
		return token
	}

	token := storedToken.Value
	if auth != nil && auth.TokenFormat != "" && auth.TokenFormat != "{{token}}" {
		return strings.ReplaceAll(auth.TokenFormat, "{{token}}", token)
	}
	return token
}
