package oauth

import (
	"context"
	"fmt"

	"google.golang.org/api/idtoken"
)

type GCPIDTokenValidator struct {
	validator *idtoken.Validator
	audience  string
}

func NewGCPIDTokenValidator(ctx context.Context, audience string) (*GCPIDTokenValidator, error) {
	v, err := idtoken.NewValidator(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating GCP ID token validator: %w", err)
	}
	return &GCPIDTokenValidator{
		validator: v,
		audience:  audience,
	}, nil
}

func (g *GCPIDTokenValidator) Validate(ctx context.Context, token string) (string, error) {
	payload, err := g.validator.Validate(ctx, token, g.audience)
	if err != nil {
		return "", fmt.Errorf("GCP ID token validation failed: %w", err)
	}

	email, _ := payload.Claims["email"].(string)
	if email == "" {
		return "", fmt.Errorf("GCP ID token missing email claim")
	}

	emailVerified, _ := payload.Claims["email_verified"].(bool)
	if !emailVerified {
		return "", fmt.Errorf("GCP ID token email not verified")
	}

	return email, nil
}
