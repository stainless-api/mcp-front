package oauthsession

import (
	"github.com/dgellow/mcp-front/internal/googleauth"
	"github.com/ory/fosite"
)

// Session extends DefaultSession with user information
type Session struct {
	*fosite.DefaultSession
	UserInfo googleauth.UserInfo `json:"user_info"`
}

// Clone implements fosite.Session
func (s *Session) Clone() fosite.Session {
	return &Session{
		DefaultSession: s.DefaultSession.Clone().(*fosite.DefaultSession),
		UserInfo:       s.UserInfo,
	}
}
