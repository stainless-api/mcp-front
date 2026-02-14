package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/dgellow/mcp-front/internal/log"
)

type ErrorCode string

const (
	ErrInvalidRequest          ErrorCode = "invalid_request"
	ErrUnauthorizedClient      ErrorCode = "unauthorized_client"
	ErrAccessDenied            ErrorCode = "access_denied"
	ErrUnsupportedResponseType ErrorCode = "unsupported_response_type"
	ErrInvalidScope            ErrorCode = "invalid_scope"
	ErrServerError             ErrorCode = "server_error"
	ErrInvalidGrant            ErrorCode = "invalid_grant"
	ErrInvalidClient           ErrorCode = "invalid_client"
	ErrUnsupportedGrantType    ErrorCode = "unsupported_grant_type"
)

type OAuthError struct {
	Code        ErrorCode `json:"error"`
	Description string    `json:"error_description,omitempty"`
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return string(e.Code)
}

func NewOAuthError(code ErrorCode, description string) *OAuthError {
	return &OAuthError{Code: code, Description: description}
}

func WriteAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI string, state string, oauthErr *OAuthError) {
	if redirectURI == "" {
		WriteTokenError(w, http.StatusBadRequest, oauthErr)
		return
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		WriteTokenError(w, http.StatusBadRequest, oauthErr)
		return
	}

	q := u.Query()
	q.Set("error", string(oauthErr.Code))
	if oauthErr.Description != "" {
		q.Set("error_description", oauthErr.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func WriteTokenError(w http.ResponseWriter, status int, oauthErr *OAuthError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(oauthErr); err != nil {
		log.LogError("Failed to encode OAuth error response: %v", err)
	}
}
