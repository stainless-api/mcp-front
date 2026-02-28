package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	emailutil "github.com/dgellow/mcp-front/internal/emailutil"
	"golang.org/x/oauth2"
)

// OIDCConfig configures a generic OIDC provider.
type OIDCConfig struct {
	// ProviderType identifies this provider (e.g., "oidc", "google", "azure").
	ProviderType string

	// Discovery URL for OIDC discovery (optional if endpoints are provided directly).
	DiscoveryURL string

	// Direct endpoint configuration (used if DiscoveryURL is not set).
	AuthorizationURL string
	TokenURL         string
	UserInfoURL      string

	// OAuth client configuration.
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// OIDCProvider implements the Provider interface for OIDC-compliant identity providers.
type OIDCProvider struct {
	providerType string
	config       oauth2.Config
	userInfoURL  string
}

// oidcDiscoveryDocument represents the OIDC discovery document.
type oidcDiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	Issuer                string `json:"issuer"`
}

// oidcUserInfoResponse represents the standard OIDC userinfo response.
type oidcUserInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// NewOIDCProvider creates a new OIDC provider.
// TODO: Add OIDC discovery caching to avoid repeated network calls.
func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	var authURL, tokenURL, userInfoURL string

	if cfg.DiscoveryURL != "" {
		discovery, err := fetchOIDCDiscovery(cfg.DiscoveryURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch OIDC discovery: %w", err)
		}
		authURL = discovery.AuthorizationEndpoint
		tokenURL = discovery.TokenEndpoint
		userInfoURL = discovery.UserInfoEndpoint
	} else {
		if cfg.AuthorizationURL == "" || cfg.TokenURL == "" || cfg.UserInfoURL == "" {
			return nil, fmt.Errorf("either discoveryUrl or all endpoints (authorizationUrl, tokenUrl, userInfoUrl) must be provided")
		}
		authURL = cfg.AuthorizationURL
		tokenURL = cfg.TokenURL
		userInfoURL = cfg.UserInfoURL
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	providerType := cfg.ProviderType
	if providerType == "" {
		providerType = "oidc"
	}

	return &OIDCProvider{
		providerType: providerType,
		config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		userInfoURL: userInfoURL,
	}, nil
}

func fetchOIDCDiscovery(discoveryURL string) (*oidcDiscoveryDocument, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("discovery endpoint returned status %d: %s", resp.StatusCode, body)
	}

	var discovery oidcDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("discovery document missing required endpoints")
	}

	return &discovery, nil
}

// Type returns the provider type.
func (p *OIDCProvider) Type() string {
	return p.providerType
}

// AuthURL generates the authorization URL.
func (p *OIDCProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
	)
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

// UserInfo fetches user identity from the OIDC userinfo endpoint.
// TODO: Add ID token validation as optimization (avoids network call).
func (p *OIDCProvider) UserInfo(ctx context.Context, token *oauth2.Token) (*Identity, error) {
	client := p.config.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("failed to get user info: status %d: %s", resp.StatusCode, body)
	}

	var userInfoResp oidcUserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfoResp); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	domain := emailutil.ExtractDomain(userInfoResp.Email)

	return &Identity{
		ProviderType:  p.providerType,
		Subject:       userInfoResp.Sub,
		Email:         userInfoResp.Email,
		EmailVerified: userInfoResp.EmailVerified,
		Name:          userInfoResp.Name,
		Picture:       userInfoResp.Picture,
		Domain:        domain,
	}, nil
}
