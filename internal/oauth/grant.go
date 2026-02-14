package oauth

import (
	"time"

	"github.com/dgellow/mcp-front/internal/idp"
)

type Grant struct {
	Code          string
	ClientID      string
	RedirectURI   string
	Identity      idp.Identity
	Scopes        []string
	Audience      []string
	PKCEChallenge string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type AuthorizeParams struct {
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	State         string   `json:"state"`
	Scopes        []string `json:"scopes,omitempty"`
	Audience      []string `json:"aud,omitempty"`
	PKCEChallenge string   `json:"pkce_challenge"`
}
