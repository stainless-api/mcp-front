package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	emailutil "github.com/dgellow/mcp-front/internal/emailutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubProvider implements the Provider interface for GitHub OAuth.
// GitHub uses OAuth 2.0 (not OIDC) and has its own API for user info and org membership.
type GitHubProvider struct {
	config oauth2.Config
}

// githubUserResponse represents GitHub's user API response.
type githubUserResponse struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

// githubEmailResponse represents an email from GitHub's emails API.
type githubEmailResponse struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// githubOrgResponse represents an org from GitHub's orgs API.
type githubOrgResponse struct {
	Login string `json:"login"`
}

// NewGitHubProvider creates a new GitHub OAuth provider.
func NewGitHubProvider(clientID, clientSecret, redirectURI string) *GitHubProvider {
	return &GitHubProvider{
		config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Scopes:       []string{"user:email", "read:org"},
			Endpoint:     github.Endpoint,
		},
	}
}

// Type returns the provider type.
func (p *GitHubProvider) Type() string {
	return "github"
}

// AuthURL generates the authorization URL.
func (p *GitHubProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.config.Exchange(ctx, code)
}

// UserInfo fetches user information from GitHub's API.
// Validates organization membership if allowedOrgs is provided.
// TODO: Consider caching org membership to reduce API calls.
func (p *GitHubProvider) UserInfo(ctx context.Context, token *oauth2.Token, allowedDomains, allowedOrgs []string) (*UserInfo, error) {
	client := p.config.Client(ctx, token)

	// Fetch user profile
	user, err := p.fetchUser(client)
	if err != nil {
		return nil, err
	}

	// Fetch primary email if not in profile
	email := user.Email
	emailVerified := false
	if email == "" {
		primaryEmail, verified, err := p.fetchPrimaryEmail(client)
		if err != nil {
			return nil, fmt.Errorf("failed to get user email: %w", err)
		}
		email = primaryEmail
		emailVerified = verified
	}

	domain := emailutil.ExtractDomain(email)

	// Validate domain if configured
	if len(allowedDomains) > 0 {
		if !slices.Contains(allowedDomains, domain) {
			return nil, fmt.Errorf("domain '%s' is not allowed. Contact your administrator", domain)
		}
	}

	// Fetch organizations
	orgs, err := p.fetchOrganizations(client)
	if err != nil {
		return nil, fmt.Errorf("failed to get user organizations: %w", err)
	}

	// Validate org membership if configured
	if len(allowedOrgs) > 0 {
		hasAllowedOrg := false
		for _, org := range orgs {
			if slices.Contains(allowedOrgs, org) {
				hasAllowedOrg = true
				break
			}
		}
		if !hasAllowedOrg {
			return nil, fmt.Errorf("user is not a member of any allowed organization. Contact your administrator")
		}
	}

	return &UserInfo{
		ProviderType:  "github",
		Subject:       fmt.Sprintf("%d", user.ID),
		Email:         email,
		EmailVerified: emailVerified,
		Name:          user.Name,
		Picture:       user.AvatarURL,
		Domain:        domain,
		Organizations: orgs,
	}, nil
}

func (p *GitHubProvider) fetchUser(client *http.Client) (*githubUserResponse, error) {
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user: status %d", resp.StatusCode)
	}

	var user githubUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}

	return &user, nil
}

func (p *GitHubProvider) fetchPrimaryEmail(client *http.Client) (string, bool, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", false, fmt.Errorf("failed to get emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("failed to get emails: status %d", resp.StatusCode)
	}

	var emails []githubEmailResponse
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("failed to decode emails: %w", err)
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, true, nil
		}
	}

	// Fallback to first verified email
	for _, email := range emails {
		if email.Verified {
			return email.Email, true, nil
		}
	}

	return "", false, fmt.Errorf("no verified email found")
}

func (p *GitHubProvider) fetchOrganizations(client *http.Client) ([]string, error) {
	resp, err := client.Get("https://api.github.com/user/orgs")
	if err != nil {
		return nil, fmt.Errorf("failed to get organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get organizations: status %d", resp.StatusCode)
	}

	var orgs []githubOrgResponse
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, fmt.Errorf("failed to decode organizations: %w", err)
	}

	orgNames := make([]string, len(orgs))
	for i, org := range orgs {
		orgNames[i] = org.Login
	}

	return orgNames, nil
}
