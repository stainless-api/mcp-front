package googleauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/dgellow/mcp-front/internal/config"
	emailutil "github.com/dgellow/mcp-front/internal/emailutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// UserInfo represents Google user information
type UserInfo struct {
	Email         string `json:"email"`
	HostedDomain  string `json:"hd"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	VerifiedEmail bool   `json:"verified_email"`
}

// GoogleAuthURL generates a Google OAuth authorization URL
func GoogleAuthURL(oauthConfig config.OAuthAuthConfig, state string) string {
	googleOAuth := newGoogleOAuth2Config(oauthConfig)
	return googleOAuth.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
	)
}

// ExchangeCodeForToken exchanges the authorization code for a token
func ExchangeCodeForToken(ctx context.Context, oauthConfig config.OAuthAuthConfig, code string) (*oauth2.Token, error) {
	googleOAuth := newGoogleOAuth2Config(oauthConfig)
	return googleOAuth.Exchange(ctx, code)
}

// ValidateUser validates the Google OAuth token and checks domain membership
func ValidateUser(ctx context.Context, oauthConfig config.OAuthAuthConfig, token *oauth2.Token) (UserInfo, error) {
	googleOAuth := newGoogleOAuth2Config(oauthConfig)
	client := googleOAuth.Client(ctx, token)
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	if customURL := os.Getenv("GOOGLE_USERINFO_URL"); customURL != "" {
		userInfoURL = customURL
	}
	resp, err := client.Get(userInfoURL)
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return UserInfo{}, fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return UserInfo{}, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Validate domain if configured
	if len(oauthConfig.AllowedDomains) > 0 {
		userDomain := emailutil.ExtractDomain(userInfo.Email)
		if !slices.Contains(oauthConfig.AllowedDomains, userDomain) {
			return UserInfo{}, fmt.Errorf("domain '%s' is not allowed. Contact your administrator", userDomain)
		}
	}

	return userInfo, nil
}

// ParseClientRequest parses MCP client registration metadata
func ParseClientRequest(metadata map[string]any) ([]string, []string, error) {
	// Extract redirect URIs
	redirectURIs := []string{}
	if uris, ok := metadata["redirect_uris"].([]any); ok {
		for _, uri := range uris {
			if uriStr, ok := uri.(string); ok {
				redirectURIs = append(redirectURIs, uriStr)
			}
		}
	}

	if len(redirectURIs) == 0 {
		return nil, nil, fmt.Errorf("no valid redirect URIs provided")
	}

	// Extract scopes, default to read/write if not provided
	scopes := []string{"read", "write"} // Default MCP scopes
	if clientScopes, ok := metadata["scope"].(string); ok {
		if strings.TrimSpace(clientScopes) != "" {
			scopes = strings.Fields(clientScopes)
		}
	}

	return redirectURIs, scopes, nil
}

// newGoogleOAuth2Config creates the OAuth2 config from our Config
func newGoogleOAuth2Config(oauthConfig config.OAuthAuthConfig) oauth2.Config {
	// Use custom OAuth endpoints if provided (for testing)
	endpoint := google.Endpoint
	if authURL := os.Getenv("GOOGLE_OAUTH_AUTH_URL"); authURL != "" {
		endpoint.AuthURL = authURL
	}
	if tokenURL := os.Getenv("GOOGLE_OAUTH_TOKEN_URL"); tokenURL != "" {
		endpoint.TokenURL = tokenURL
	}

	return oauth2.Config{
		ClientID:     oauthConfig.GoogleClientID,
		ClientSecret: string(oauthConfig.GoogleClientSecret),
		RedirectURL:  oauthConfig.GoogleRedirectURI,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     endpoint,
	}
}
