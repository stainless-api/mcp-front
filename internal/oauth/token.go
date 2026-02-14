package oauth

import (
	"encoding/json"
	"net/http"

	"github.com/dgellow/mcp-front/internal/idp"
	"github.com/dgellow/mcp-front/internal/log"
)

type AccessTokenClaims struct {
	TokenID  string       `json:"jti"`
	ClientID string       `json:"cid"`
	Identity idp.Identity `json:"identity"`
	Scopes   []string     `json:"scopes,omitempty"`
	Audience []string     `json:"aud,omitempty"`
}

type RefreshTokenClaims struct {
	TokenID  string       `json:"jti"`
	GrantID  string       `json:"gid"`
	ClientID string       `json:"cid"`
	Identity idp.Identity `json:"identity"`
	Scopes   []string     `json:"scopes,omitempty"`
	Audience []string     `json:"aud,omitempty"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func WriteTokenResponse(w http.ResponseWriter, pair *TokenPair) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(pair); err != nil {
		log.LogError("Failed to encode token response: %v", err)
	}
}
