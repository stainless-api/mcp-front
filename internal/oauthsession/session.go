package oauthsession

import (
	"time"

	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/ory/fosite"
)

// Session extends DefaultSession with user information
type Session struct {
	*fosite.DefaultSession
	UserInfo idp.UserInfo `json:"user_info"`
}

// NewSession creates a new session with user info
func NewSession(userInfo idp.UserInfo) *Session {
	return &Session{
		DefaultSession: &fosite.DefaultSession{
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().Add(time.Hour),
				fosite.RefreshToken: time.Now().Add(24 * time.Hour),
			},
			Username: userInfo.Email,
			Subject:  userInfo.Email,
		},
		UserInfo: userInfo,
	}
}

// Clone implements fosite.Session
func (s *Session) Clone() fosite.Session {
	return &Session{
		DefaultSession: s.DefaultSession.Clone().(*fosite.DefaultSession),
		UserInfo:       s.UserInfo,
	}
}
