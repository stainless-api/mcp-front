package browserauth

import "time"

// SessionCookie represents the data stored in encrypted browser session cookies
type SessionCookie struct {
	Email   string    `json:"email"`
	Expires time.Time `json:"expires"`
}

// AuthorizationState represents the OAuth authorization code flow state parameter
type AuthorizationState struct {
	Nonce     string `json:"nonce"`
	ReturnURL string `json:"return_url"`
}
