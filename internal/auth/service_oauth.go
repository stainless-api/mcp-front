package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
	"golang.org/x/oauth2"
)

const (
	// OAuthStateExpiry is how long OAuth state parameters remain valid
	OAuthStateExpiry = 10 * time.Minute

	// TokenRefreshThreshold is how early to refresh tokens before expiry
	// Set to 5 minutes to prevent tokens expiring mid-operation when users
	// are in Claude and cannot easily re-authenticate
	TokenRefreshThreshold = 5 * time.Minute
)

// ServiceOAuthClient handles OAuth flows for external MCP services
type ServiceOAuthClient struct {
	storage     storage.UserTokenStore
	baseURL     string
	httpClient  *http.Client
	stateSigner crypto.TokenSigner
}

// ServiceOAuthState stores OAuth flow state for external service authentication (mcp-front → external service)
type ServiceOAuthState struct {
	Service   string    `json:"service"`
	UserEmail string    `json:"user_email"`
	CreatedAt time.Time `json:"created_at"`
}

// NewServiceOAuthClient creates a new OAuth client for external services
func NewServiceOAuthClient(storage storage.UserTokenStore, baseURL string, signingKey []byte) *ServiceOAuthClient {
	return &ServiceOAuthClient{
		storage:     storage,
		baseURL:     baseURL,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		stateSigner: crypto.NewTokenSigner(signingKey, OAuthStateExpiry),
	}
}

// StartOAuthFlow initiates OAuth flow for a service
func (c *ServiceOAuthClient) StartOAuthFlow(
	ctx context.Context,
	userEmail string,
	serviceName string,
	serviceConfig *config.MCPClientConfig,
) (string, error) {
	if serviceConfig.UserAuthentication == nil ||
		serviceConfig.UserAuthentication.Type != config.UserAuthTypeOAuth {
		return "", fmt.Errorf("service %s does not support OAuth", serviceName)
	}

	auth := serviceConfig.UserAuthentication

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     string(auth.ClientID),
		ClientSecret: string(auth.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  auth.AuthorizationURL,
			TokenURL: auth.TokenURL,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/callback/%s", c.baseURL, serviceName),
		Scopes:      auth.Scopes,
	}

	// Generate signed state parameter (stateless - no cache needed)
	stateData := ServiceOAuthState{
		Service:   serviceName,
		UserEmail: userEmail,
		CreatedAt: time.Now(),
	}

	state, err := c.stateSigner.Sign(stateData)
	if err != nil {
		return "", fmt.Errorf("failed to sign state: %w", err)
	}

	// Generate authorization URL
	authURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	log.LogInfoWithFields("service_oauth", "Starting OAuth flow", map[string]any{
		"service":  serviceName,
		"user":     userEmail,
		"authURL":  authURL,
		"redirect": oauth2Config.RedirectURL,
	})

	return authURL, nil
}

// HandleCallback processes OAuth callback
func (c *ServiceOAuthClient) HandleCallback(
	ctx context.Context,
	serviceName string,
	code string,
	state string,
	serviceConfig *config.MCPClientConfig,
) (userEmail string, err error) {
	// Verify and decode signed state
	var stateData ServiceOAuthState
	if err := c.stateSigner.Verify(state, &stateData); err != nil {
		return "", fmt.Errorf("invalid or expired state parameter: %w", err)
	}

	// Validate service matches
	if stateData.Service != serviceName {
		return "", fmt.Errorf("service mismatch in OAuth callback")
	}

	auth := serviceConfig.UserAuthentication
	if auth == nil || auth.Type != config.UserAuthTypeOAuth {
		return "", fmt.Errorf("service %s does not support OAuth", serviceName)
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     string(auth.ClientID),
		ClientSecret: string(auth.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  auth.AuthorizationURL,
			TokenURL: auth.TokenURL,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/callback/%s", c.baseURL, serviceName),
		Scopes:      auth.Scopes,
	}

	// Exchange code for token
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to exchange code for token", map[string]any{
			"service": serviceName,
			"error":   err.Error(),
		})
		return "", fmt.Errorf("failed to exchange code: %w", err)
	}

	// Store the token
	storedToken := &storage.StoredToken{
		Type: storage.TokenTypeOAuth,
		OAuthData: &storage.OAuthTokenData{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresAt:    token.Expiry,
			TokenType:    token.TokenType,
			Scopes:       auth.Scopes,
		},
		UpdatedAt: time.Now(),
	}

	if err := c.storage.SetUserToken(ctx, stateData.UserEmail, serviceName, storedToken); err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to store OAuth token", map[string]any{
			"service": serviceName,
			"user":    stateData.UserEmail,
			"error":   err.Error(),
		})
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	log.LogInfoWithFields("service_oauth", "OAuth flow completed successfully", map[string]any{
		"service": serviceName,
		"user":    stateData.UserEmail,
	})

	return stateData.UserEmail, nil
}

// RefreshToken refreshes an OAuth token if needed
func (c *ServiceOAuthClient) RefreshToken(
	ctx context.Context,
	userEmail string,
	serviceName string,
	serviceConfig *config.MCPClientConfig,
) error {
	// Get current token
	storedToken, err := c.storage.GetUserToken(ctx, userEmail, serviceName)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	if storedToken.Type != storage.TokenTypeOAuth || storedToken.OAuthData == nil {
		return fmt.Errorf("token is not an OAuth token")
	}

	// Early refresh strategy: Refresh tokens TokenRefreshThreshold before expiry
	//
	// Why 5 minutes?
	// - Users are in Claude.ai, not mcp-front UI. If token expires mid-session,
	//   they see cryptic "tool failed" errors with no way to re-auth without
	//   leaving Claude.
	// - Stdio processes are created on-demand. Token is fetched from storage and
	//   injected into process env. If storage has expired token, process fails
	//   to connect to external service.
	// - Early refresh prevents these failures. Cost is negligible (one HTTP request
	//   per service per hour vs broken user workflow).
	//
	// Why not background refresh job?
	// - mcp-front is request-driven. Tokens are fetched when stdio sessions are
	//   created (user triggers operation in Claude). Refreshing on request path
	//   is simpler and aligns with the architecture.
	// - Background jobs require distributed coordination for multi-instance deploys,
	//   lifecycle management, and handling refresh failures asynchronously.
	if time.Until(storedToken.OAuthData.ExpiresAt) > TokenRefreshThreshold {
		return nil // Token still valid, no refresh needed
	}

	if storedToken.OAuthData.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	auth := serviceConfig.UserAuthentication
	if auth == nil || auth.Type != config.UserAuthTypeOAuth {
		return fmt.Errorf("service configuration missing OAuth settings")
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     string(auth.ClientID),
		ClientSecret: string(auth.ClientSecret),
		Endpoint: oauth2.Endpoint{
			AuthURL:  auth.AuthorizationURL,
			TokenURL: auth.TokenURL,
		},
		Scopes: auth.Scopes,
	}

	// Create token for refresh
	oldToken := &oauth2.Token{
		AccessToken:  storedToken.OAuthData.AccessToken,
		RefreshToken: storedToken.OAuthData.RefreshToken,
		Expiry:       storedToken.OAuthData.ExpiresAt,
		TokenType:    storedToken.OAuthData.TokenType,
	}

	// Use ReuseTokenSourceWithExpiry to enforce our 5-minute early refresh threshold.
	// The default TokenSource only refreshes when token is expired. We want to refresh
	// earlier to prevent tokens expiring mid-operation. The earlyExpiry parameter
	// tells the oauth2 library to consider tokens expired 5 minutes before their
	// actual expiry time.
	//
	// Division of responsibility:
	// - We decide WHEN to refresh (5-minute threshold via our check + earlyExpiry)
	// - oauth2 library decides HOW to refresh (HTTP request format, error handling,
	//   refresh token rotation, provider-specific quirks across OAuth providers)
	baseSource := oauth2Config.TokenSource(ctx, oldToken)
	earlyRefreshSource := oauth2.ReuseTokenSourceWithExpiry(oldToken, baseSource, TokenRefreshThreshold)
	newToken, err := earlyRefreshSource.Token()
	if err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to refresh token", map[string]any{
			"service": serviceName,
			"user":    userEmail,
			"error":   err.Error(),
		})
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	// Update stored token
	storedToken.OAuthData.AccessToken = newToken.AccessToken
	if newToken.RefreshToken != "" {
		storedToken.OAuthData.RefreshToken = newToken.RefreshToken
	}
	storedToken.OAuthData.ExpiresAt = newToken.Expiry
	storedToken.UpdatedAt = time.Now()

	if err := c.storage.SetUserToken(ctx, userEmail, serviceName, storedToken); err != nil {
		return fmt.Errorf("failed to store refreshed token: %w", err)
	}

	log.LogInfoWithFields("service_oauth", "Token refreshed successfully", map[string]any{
		"service": serviceName,
		"user":    userEmail,
		"expiry":  newToken.Expiry,
	})

	return nil
}

// GetConnectURL generates the OAuth connect URL for a service
func (c *ServiceOAuthClient) GetConnectURL(serviceName string, returnPath string) string {
	params := url.Values{}
	params.Set("service", serviceName)
	if returnPath != "" {
		params.Set("return", returnPath)
	}
	return fmt.Sprintf("%s/oauth/connect?%s", c.baseURL, params.Encode())
}

// ParseTokenResponse parses a token response for custom OAuth implementations
func ParseTokenResponse(body []byte) (*oauth2.Token, error) {
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	token := &oauth2.Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		TokenType:    resp.TokenType,
	}

	if resp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}

	if resp.Scope != "" {
		token = token.WithExtra(map[string]any{
			"scope": strings.Split(resp.Scope, " "),
		})
	}

	return token, nil
}
