package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// serviceStorage combines the storage interfaces needed by ServiceOAuthClient
type serviceStorage interface {
	storage.UserTokenStore
	storage.ServiceRegistrationStore
}

// ServiceOAuthClient handles OAuth flows for external MCP services
type ServiceOAuthClient struct {
	storage     serviceStorage
	baseURL     string
	httpClient  *http.Client
	stateSigner crypto.TokenSigner
}

// ServiceOAuthState stores OAuth flow state for external service authentication (mcp-front → external service)
type ServiceOAuthState struct {
	Service   string    `json:"service"`
	UserEmail string    `json:"user_email"`
	ReturnURL string    `json:"return_url,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// CallbackResult contains the result of a successful OAuth callback
type CallbackResult struct {
	UserEmail string
	ReturnURL string
}

// NewServiceOAuthClient creates a new OAuth client for external services
func NewServiceOAuthClient(store serviceStorage, baseURL string, signingKey []byte) *ServiceOAuthClient {
	return &ServiceOAuthClient{
		storage:     store,
		baseURL:     baseURL,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		stateSigner: crypto.NewTokenSigner(signingKey, OAuthStateExpiry),
	}
}

// getOAuth2Config builds an oauth2.Config for the given service, performing dynamic
// client registration if no clientId is configured.
func (c *ServiceOAuthClient) getOAuth2Config(ctx context.Context, serviceName string, auth *config.UserAuthentication) (*oauth2.Config, error) {
	clientID := string(auth.ClientID)
	clientSecret := string(auth.ClientSecret)

	if clientID == "" {
		reg, err := c.getOrRegisterClient(ctx, serviceName, auth)
		if err != nil {
			return nil, fmt.Errorf("dynamic client registration failed: %w", err)
		}
		clientID = reg.ClientID
		clientSecret = reg.ClientSecret
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  auth.AuthorizationURL,
			TokenURL: auth.TokenURL,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/callback/%s", c.baseURL, serviceName),
		Scopes:      auth.Scopes,
	}, nil
}

// getOrRegisterClient returns a stored service registration, registering dynamically if needed.
func (c *ServiceOAuthClient) getOrRegisterClient(ctx context.Context, serviceName string, auth *config.UserAuthentication) (*storage.ServiceRegistration, error) {
	reg, err := c.storage.GetServiceRegistration(ctx, serviceName)
	if err == nil {
		if reg.ExpiresAt.IsZero() || time.Now().Before(reg.ExpiresAt) {
			return reg, nil
		}
		log.LogInfoWithFields("service_oauth", "Service registration expired, re-registering", map[string]any{
			"service": serviceName,
		})
	} else if !errors.Is(err, storage.ErrServiceRegistrationNotFound) {
		return nil, fmt.Errorf("failed to get service registration: %w", err)
	}

	return c.registerClient(ctx, serviceName, auth)
}

// registerClient performs RFC 7591 dynamic client registration with the upstream service.
func (c *ServiceOAuthClient) registerClient(ctx context.Context, serviceName string, auth *config.UserAuthentication) (*storage.ServiceRegistration, error) {
	registrationURL, err := c.discoverRegistrationEndpoint(ctx, auth.AuthorizationURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover registration endpoint: %w", err)
	}

	redirectURI := fmt.Sprintf("%s/oauth/callback/%s", c.baseURL, serviceName)

	reqBody := map[string]any{
		"redirect_uris":              []string{redirectURI},
		"client_name":                "mcp-front",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
	}
	if len(auth.Scopes) > 0 {
		reqBody["scope"] = strings.Join(auth.Scopes, " ")
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationURL, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, body)
	}

	var regResp struct {
		ClientID              string `json:"client_id"`
		ClientSecret          string `json:"client_secret,omitempty"`
		ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %w", err)
	}

	if regResp.ClientID == "" {
		return nil, fmt.Errorf("registration response missing client_id")
	}

	reg := &storage.ServiceRegistration{
		ServiceName:  serviceName,
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		CreatedAt:    time.Now(),
	}
	if regResp.ClientSecretExpiresAt > 0 {
		reg.ExpiresAt = time.Unix(regResp.ClientSecretExpiresAt, 0)
	}

	if err := c.storage.SetServiceRegistration(ctx, serviceName, reg); err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to store service registration", map[string]any{
			"service": serviceName,
			"error":   err.Error(),
		})
	}

	log.LogInfoWithFields("service_oauth", "Dynamically registered client with service", map[string]any{
		"service":   serviceName,
		"client_id": regResp.ClientID,
	})

	return reg, nil
}

// discoverRegistrationEndpoint fetches OAuth server metadata to find the registration endpoint.
func (c *ServiceOAuthClient) discoverRegistrationEndpoint(ctx context.Context, authorizationURL string) (string, error) {
	u, err := url.Parse(authorizationURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse authorization URL: %w", err)
	}

	metaURL := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", u.Scheme, u.Host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create metadata request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OAuth metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata endpoint returned status %d", resp.StatusCode)
	}

	var meta struct {
		RegistrationEndpoint string `json:"registration_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("failed to decode OAuth metadata: %w", err)
	}

	if meta.RegistrationEndpoint == "" {
		return "", fmt.Errorf("OAuth metadata missing registration_endpoint")
	}

	return meta.RegistrationEndpoint, nil
}

// StartOAuthFlow initiates OAuth flow for a service
func (c *ServiceOAuthClient) StartOAuthFlow(
	ctx context.Context,
	userEmail string,
	serviceName string,
	returnURL string,
	serviceConfig *config.MCPClientConfig,
) (string, error) {
	if serviceConfig.UserAuthentication == nil ||
		serviceConfig.UserAuthentication.Type != config.UserAuthTypeOAuth {
		return "", fmt.Errorf("service %s does not support OAuth", serviceName)
	}

	auth := serviceConfig.UserAuthentication

	oauth2Config, err := c.getOAuth2Config(ctx, serviceName, auth)
	if err != nil {
		return "", fmt.Errorf("failed to get OAuth config: %w", err)
	}

	// Generate signed state parameter (stateless - no cache needed)
	stateData := ServiceOAuthState{
		Service:   serviceName,
		UserEmail: userEmail,
		ReturnURL: returnURL,
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
) (*CallbackResult, error) {
	// Verify and decode signed state
	var stateData ServiceOAuthState
	if err := c.stateSigner.Verify(state, &stateData); err != nil {
		return nil, fmt.Errorf("invalid or expired state parameter: %w", err)
	}

	// Validate service matches
	if stateData.Service != serviceName {
		return nil, fmt.Errorf("service mismatch in OAuth callback")
	}

	auth := serviceConfig.UserAuthentication
	if auth == nil || auth.Type != config.UserAuthTypeOAuth {
		return nil, fmt.Errorf("service %s does not support OAuth", serviceName)
	}

	oauth2Config, err := c.getOAuth2Config(ctx, serviceName, auth)
	if err != nil {
		return "", returnURL, fmt.Errorf("failed to get OAuth config: %w", err)
	}

	// Exchange code for token
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		log.LogErrorWithFields("service_oauth", "Failed to exchange code for token", map[string]any{
			"service": serviceName,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to exchange code: %w", err)
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
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	log.LogInfoWithFields("service_oauth", "OAuth flow completed successfully", map[string]any{
		"service": serviceName,
		"user":    stateData.UserEmail,
	})

	return &CallbackResult{
		UserEmail: stateData.UserEmail,
		ReturnURL: stateData.ReturnURL,
	}, nil
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

	oauth2Config, err := c.getOAuth2Config(ctx, serviceName, auth)
	if err != nil {
		return fmt.Errorf("failed to get OAuth config: %w", err)
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
