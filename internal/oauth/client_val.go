package oauth

import (
	"fmt"
	"slices"

	"golang.org/x/crypto/bcrypt"
)

type Client interface {
	GetID() string
	GetSecret() []byte
	GetRedirectURIs() []string
	GetScopes() []string
	GetAudience() []string
	IsPublic() bool
}

func ValidateRedirectURI(redirectURI string, client Client) error {
	if !slices.Contains(client.GetRedirectURIs(), redirectURI) {
		return fmt.Errorf("redirect_uri not registered for this client")
	}
	return nil
}

func ValidateClientSecret(providedSecret string, client Client) error {
	if client.IsPublic() {
		return nil
	}
	if err := bcrypt.CompareHashAndPassword(client.GetSecret(), []byte(providedSecret)); err != nil {
		return fmt.Errorf("invalid client secret")
	}
	return nil
}

func ValidateScopes(requested []string, client Client) error {
	allowed := client.GetScopes()
	for _, scope := range requested {
		if !slices.Contains(allowed, scope) {
			return fmt.Errorf("scope %q not allowed for this client", scope)
		}
	}
	return nil
}
