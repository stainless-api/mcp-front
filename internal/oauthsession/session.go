package oauthsession

import (
	"time"

	"github.com/dgellow/mcp-front/internal/googleauth"
	"github.com/ory/fosite"
)

// Session extends DefaultSession with user information
type Session struct {
	*fosite.DefaultSession
	UserInfo googleauth.UserInfo `json:"user_info,omitempty"`
}

// NewSession creates a new session with user info
func NewSession(userInfo googleauth.UserInfo) *Session {
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
