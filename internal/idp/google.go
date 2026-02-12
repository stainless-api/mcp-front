package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	emailutil "github.com/dgellow/mcp-front/internal/emailutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleProvider implements the Provider interface for Google OAuth.
// Google has specific quirks like `hd` for hosted domain and `verified_email` field.
type GoogleProvider struct {
	config      oauth2.Config
	userInfoURL string
}

// googleUserInfoResponse represents Google's userinfo response.
// Note: Google uses `hd` for hosted domain and `verified_email` instead of OIDC standard `email_verified`.
type googleUserInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	HostedDomain  string `json:"hd"`
}

// NewGoogleProvider creates a new Google OAuth provider.
// Optional endpoint overrides (authorizationURL, tokenURL, userInfoURL) allow
// pointing at a non-Google server — useful for testing or corporate proxies.
func NewGoogleProvider(clientID, clientSecret, redirectURI, authorizationURL, tokenURL, userInfoURL string) *GoogleProvider {
	endpoint := google.Endpoint
	if authorizationURL != "" {
		endpoint.AuthURL = authorizationURL
	}
	if tokenURL != "" {
		endpoint.TokenURL = tokenURL
	}

	uiURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	if userInfoURL != "" {
		uiURL = userInfoURL
	}

	return &GoogleProvider{
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     endpoint,
		},
		userInfoURL: uiURL,
	}
}

// Type returns the provider type.
func (p *GoogleProvider) Type() string {
	return "google"
}

// AuthURL generates the authorization URL.
func (p *GoogleProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
	)
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

// UserInfo fetches user identity from Google's userinfo endpoint.
func (p *GoogleProvider) UserInfo(ctx context.Context, token *oauth2.Token) (*Identity, error) {
	client := p.config.Client(ctx, token)

	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	var googleUser googleUserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Use Google's hosted domain if available, otherwise derive from email
	domain := googleUser.HostedDomain
	if domain == "" {
		domain = emailutil.ExtractDomain(googleUser.Email)
	}

	return &Identity{
		ProviderType:  "google",
		Subject:       googleUser.Sub,
		Email:         googleUser.Email,
		EmailVerified: googleUser.VerifiedEmail,
		Name:          googleUser.Name,
		Picture:       googleUser.Picture,
		Domain:        domain,
	}, nil
}
