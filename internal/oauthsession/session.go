package oauthsession

import (
	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/ory/fosite"
)

// Session extends DefaultSession with user information
type Session struct {
	*fosite.DefaultSession
	Identity idp.Identity `json:"identity"`
}

// Clone implements fosite.Session
func (s *Session) Clone() fosite.Session {
	return &Session{
		DefaultSession: s.DefaultSession.Clone().(*fosite.DefaultSession),
		Identity:       s.Identity,
	}
}
