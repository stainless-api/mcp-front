package session

import (
	"time"

	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/ory/fosite"
)

// OAuthSession extends DefaultSession with user information for the OAuth flow
type OAuthSession struct {
	*fosite.DefaultSession
	Identity idp.Identity `json:"identity"`
}

// Clone implements fosite.Session
func (s *OAuthSession) Clone() fosite.Session {
	return &OAuthSession{
		DefaultSession: s.DefaultSession.Clone().(*fosite.DefaultSession),
		Identity:       s.Identity,
	}
}

// BrowserCookie represents the data stored in encrypted browser session cookies
type BrowserCookie struct {
	Email    string    `json:"email"`
	Provider string    `json:"provider"` // IDP that authenticated this user (e.g., "google", "azure", "github")
	Expires  time.Time `json:"expires"`
}

// AuthorizationState represents the OAuth authorization code flow state parameter
type AuthorizationState struct {
	Nonce     string `json:"nonce"`
	ReturnURL string `json:"return_url"`
}
