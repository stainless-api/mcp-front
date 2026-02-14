package session

import "time"

type BrowserCookie struct {
	Email    string    `json:"email"`
	Provider string    `json:"provider"`
	Expires  time.Time `json:"expires"`
}

func (c BrowserCookie) IsExpired() bool {
	return time.Now().After(c.Expires)
}

type AuthorizationState struct {
	Nonce     string `json:"nonce"`
	ReturnURL string `json:"return_url"`
}
