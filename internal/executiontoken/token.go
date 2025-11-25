package executiontoken

import (
	"fmt"
	"time"

	"github.com/dgellow/mcp-front/internal/crypto"
)

// Claims represents the claims for an execution token
// The token is lightweight and just references a session ID
// All policy (paths, limits, etc.) is stored in the session
type Claims struct {
	SessionID string    `json:"session_id"`
	IssuedAt  time.Time `json:"issued_at"`
}

// Generator generates execution tokens
type Generator struct {
	signer crypto.TokenSigner
}

// Validator validates execution tokens
type Validator struct {
	signer crypto.TokenSigner
}

// NewGenerator creates a token generator
func NewGenerator(signingKey []byte, defaultTTL time.Duration) *Generator {
	return &Generator{
		signer: crypto.NewTokenSigner(signingKey, defaultTTL),
	}
}

// NewValidator creates a token validator
func NewValidator(signingKey []byte, defaultTTL time.Duration) *Validator {
	return &Validator{
		signer: crypto.NewTokenSigner(signingKey, defaultTTL),
	}
}

// Generate creates a new execution token for a session
func (g *Generator) Generate(sessionID string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("session ID is required")
	}

	claims := Claims{
		SessionID: sessionID,
		IssuedAt:  time.Now(),
	}

	token, err := g.signer.Sign(claims)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return token, nil
}

// Validate validates and parses an execution token
func (v *Validator) Validate(token string) (*Claims, error) {
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	var claims Claims
	if err := v.signer.Verify(token, &claims); err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Validate session ID is present
	if claims.SessionID == "" {
		return nil, fmt.Errorf("token missing session ID")
	}

	return &claims, nil
}
