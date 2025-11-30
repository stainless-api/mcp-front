package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGitHubProvider_Type(t *testing.T) {
	provider := NewGitHubProvider("client-id", "client-secret", "https://example.com/callback", nil)
	assert.Equal(t, "github", provider.Type())
}

func TestGitHubProvider_AuthURL(t *testing.T) {
	provider := NewGitHubProvider("client-id", "client-secret", "https://example.com/callback", nil)

	authURL := provider.AuthURL("test-state")

	assert.Contains(t, authURL, "github.com")
	assert.Contains(t, authURL, "state=test-state")
	assert.Contains(t, authURL, "client_id=client-id")
}

func TestGitHubProvider_UserInfo(t *testing.T) {
	tests := []struct {
		name                  string
		userResp              githubUserResponse
		emailsResp            []githubEmailResponse
		orgsResp              []githubOrgResponse
		allowedDomains        []string
		allowedOrgs           []string
		wantErr               bool
		errContains           string
		expectedEmail         string
		expectedEmailVerified bool
		expectedDomain        string
		expectedOrgs          []string
	}{
		{
			name: "user_with_public_email",
			userResp: githubUserResponse{
				ID:        12345,
				Login:     "testuser",
				Email:     "user@company.com",
				Name:      "Test User",
				AvatarURL: "https://github.com/avatar.jpg",
			},
			expectedEmail:         "user@company.com",
			expectedEmailVerified: true, // Public emails in GitHub profile are verified
			expectedDomain:        "company.com",
			expectedOrgs:          nil, // Orgs not fetched when allowedOrgs is empty
		},
		{
			name: "user_without_public_email_fetches_from_api",
			userResp: githubUserResponse{
				ID:    12345,
				Login: "testuser",
				Name:  "Test User",
			},
			emailsResp: []githubEmailResponse{
				{Email: "secondary@other.com", Primary: false, Verified: true},
				{Email: "primary@company.com", Primary: true, Verified: true},
			},
			expectedEmail:         "primary@company.com",
			expectedEmailVerified: true,
			expectedDomain:        "company.com",
			expectedOrgs:          nil, // Orgs not fetched when allowedOrgs is empty
		},
		{
			name: "user_with_unverified_primary_falls_back_to_verified",
			userResp: githubUserResponse{
				ID:    12345,
				Login: "testuser",
			},
			emailsResp: []githubEmailResponse{
				{Email: "primary@company.com", Primary: true, Verified: false},
				{Email: "verified@company.com", Primary: false, Verified: true},
			},
			expectedEmail:         "verified@company.com",
			expectedEmailVerified: true,
			expectedDomain:        "company.com",
			expectedOrgs:          nil, // Orgs not fetched when allowedOrgs is empty
		},
		{
			name: "domain_validation_success",
			userResp: githubUserResponse{
				ID:    12345,
				Login: "testuser",
				Email: "user@company.com",
			},
			allowedDomains:        []string{"company.com"},
			expectedEmail:         "user@company.com",
			expectedEmailVerified: true,
			expectedDomain:        "company.com",
			expectedOrgs:          nil, // Orgs not fetched when allowedOrgs is empty
		},
		{
			name: "domain_validation_failure",
			userResp: githubUserResponse{
				ID:    12345,
				Login: "testuser",
				Email: "user@other.com",
			},
			allowedDomains: []string{"company.com"},
			wantErr:        true,
			errContains:    "domain 'other.com' is not allowed",
		},
		{
			name: "org_validation_success",
			userResp: githubUserResponse{
				ID:    12345,
				Login: "testuser",
				Email: "user@gmail.com",
			},
			orgsResp:              []githubOrgResponse{{Login: "allowed-org"}, {Login: "other-org"}},
			allowedOrgs:           []string{"allowed-org"},
			expectedEmail:         "user@gmail.com",
			expectedEmailVerified: true,
			expectedDomain:        "gmail.com",
			expectedOrgs:          []string{"allowed-org", "other-org"},
		},
		{
			name: "org_validation_failure",
			userResp: githubUserResponse{
				ID:    12345,
				Login: "testuser",
				Email: "user@gmail.com",
			},
			orgsResp:    []githubOrgResponse{{Login: "other-org"}},
			allowedOrgs: []string{"required-org"},
			wantErr:     true,
			errContains: "not a member of any allowed organization",
		},
		{
			name: "user_with_no_orgs_restriction",
			userResp: githubUserResponse{
				ID:    12345,
				Login: "testuser",
				Email: "user@gmail.com",
			},
			expectedEmail:         "user@gmail.com",
			expectedEmailVerified: true,
			expectedDomain:        "gmail.com",
			expectedOrgs:          nil, // Orgs not fetched when allowedOrgs is empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				switch r.URL.Path {
				case "/user":
					err := json.NewEncoder(w).Encode(tt.userResp)
					require.NoError(t, err)
				case "/user/emails":
					err := json.NewEncoder(w).Encode(tt.emailsResp)
					require.NoError(t, err)
				case "/user/orgs":
					err := json.NewEncoder(w).Encode(tt.orgsResp)
					require.NoError(t, err)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Create provider with test server endpoints and allowedOrgs
			provider := &GitHubProvider{
				config: oauth2.Config{
					ClientID:     "test-client",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/callback",
					Scopes:       []string{"user:email", "read:org"},
					Endpoint: oauth2.Endpoint{
						AuthURL:  server.URL + "/authorize",
						TokenURL: server.URL + "/token",
					},
				},
				apiBaseURL:  server.URL,
				allowedOrgs: tt.allowedOrgs,
			}

			token := &oauth2.Token{AccessToken: "test-token"}
			userInfo, err := provider.UserInfo(context.Background(), token, tt.allowedDomains)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, userInfo)
			assert.Equal(t, "github", userInfo.ProviderType)
			assert.Equal(t, tt.expectedEmail, userInfo.Email)
			assert.Equal(t, tt.expectedEmailVerified, userInfo.EmailVerified)
			assert.Equal(t, tt.expectedDomain, userInfo.Domain)
			assert.Equal(t, tt.expectedOrgs, userInfo.Organizations)
		})
	}
}

func TestGitHubProvider_UserInfo_APIErrors(t *testing.T) {
	tests := []struct {
		name        string
		userStatus  int
		errContains string
	}{
		{
			name:        "user_api_error",
			userStatus:  http.StatusInternalServerError,
			errContains: "status 500",
		},
		{
			name:        "user_unauthorized",
			userStatus:  http.StatusUnauthorized,
			errContains: "status 401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.userStatus)
			}))
			defer server.Close()

			provider := &GitHubProvider{
				config: oauth2.Config{
					ClientID:     "test-client",
					ClientSecret: "test-secret",
				},
				apiBaseURL: server.URL,
			}

			token := &oauth2.Token{AccessToken: "test-token"}
			_, err := provider.UserInfo(context.Background(), token, nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestGitHubProvider_UserInfo_NoVerifiedEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/user":
			err := json.NewEncoder(w).Encode(githubUserResponse{ID: 123, Login: "test"})
			require.NoError(t, err)
		case "/user/emails":
			err := json.NewEncoder(w).Encode([]githubEmailResponse{
				{Email: "unverified@example.com", Primary: true, Verified: false},
			})
			require.NoError(t, err)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	provider := &GitHubProvider{
		config:     oauth2.Config{ClientID: "test"},
		apiBaseURL: server.URL,
	}

	token := &oauth2.Token{AccessToken: "test-token"}
	_, err := provider.UserInfo(context.Background(), token, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no verified email")
}
