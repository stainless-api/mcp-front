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

func TestGoogleProvider_Type(t *testing.T) {
	provider := NewGoogleProvider("client-id", "client-secret", "https://example.com/callback", nil)
	assert.Equal(t, "google", provider.Type())
}

func TestGoogleProvider_AuthURL(t *testing.T) {
	provider := NewGoogleProvider("client-id", "client-secret", "https://example.com/callback", nil)

	authURL := provider.AuthURL("test-state")

	assert.Contains(t, authURL, "accounts.google.com")
	assert.Contains(t, authURL, "state=test-state")
	assert.Contains(t, authURL, "client_id=client-id")
	assert.Contains(t, authURL, "redirect_uri=")
	assert.Contains(t, authURL, "access_type=offline")
}

func TestGoogleProvider_UserInfo(t *testing.T) {
	tests := []struct {
		name            string
		userInfoResp    googleUserInfoResponse
		allowedDomains  []string
		wantErr         bool
		errContains     string
		expectedDomain  string
		expectedSubject string
	}{
		{
			name: "valid_user_with_hosted_domain",
			userInfoResp: googleUserInfoResponse{
				Sub:           "12345",
				Email:         "user@company.com",
				VerifiedEmail: true,
				Name:          "Test User",
				Picture:       "https://example.com/photo.jpg",
				HostedDomain:  "company.com",
			},
			allowedDomains:  []string{"company.com"},
			wantErr:         false,
			expectedDomain:  "company.com",
			expectedSubject: "12345",
		},
		{
			name: "valid_user_without_hosted_domain_derives_from_email",
			userInfoResp: googleUserInfoResponse{
				Sub:           "12345",
				Email:         "user@gmail.com",
				VerifiedEmail: true,
				Name:          "Test User",
			},
			allowedDomains:  nil,
			wantErr:         false,
			expectedDomain:  "gmail.com",
			expectedSubject: "12345",
		},
		{
			name: "domain_not_allowed",
			userInfoResp: googleUserInfoResponse{
				Sub:           "12345",
				Email:         "user@other.com",
				VerifiedEmail: true,
				Name:          "Test User",
				HostedDomain:  "other.com",
			},
			allowedDomains: []string{"company.com"},
			wantErr:        true,
			errContains:    "domain 'other.com' is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(tt.userInfoResp)
				require.NoError(t, err)
			}))
			defer server.Close()

			provider := &GoogleProvider{
				config: oauth2.Config{
					ClientID:     "test-client",
					ClientSecret: "test-secret",
					RedirectURL:  "https://example.com/callback",
					Scopes:       []string{"openid", "profile", "email"},
					Endpoint: oauth2.Endpoint{
						AuthURL:  server.URL + "/authorize",
						TokenURL: server.URL + "/token",
					},
				},
				userInfoURL:    server.URL,
				allowedDomains: tt.allowedDomains,
			}
			token := &oauth2.Token{AccessToken: "test-token"}

			userInfo, err := provider.UserInfo(context.Background(), token)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, userInfo)
			assert.Equal(t, "google", userInfo.ProviderType)
			assert.Equal(t, tt.expectedSubject, userInfo.Subject)
			assert.Equal(t, tt.expectedDomain, userInfo.Domain)
			assert.Equal(t, tt.userInfoResp.Email, userInfo.Email)
			assert.Equal(t, tt.userInfoResp.VerifiedEmail, userInfo.EmailVerified)
		})
	}
}

func TestGoogleProvider_UserInfo_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	provider := &GoogleProvider{
		config: oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		},
		userInfoURL: server.URL,
	}
	token := &oauth2.Token{AccessToken: "test-token"}

	_, err := provider.UserInfo(context.Background(), token)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}
