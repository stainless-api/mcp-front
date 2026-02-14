package crypto

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CSRFProtection provides stateless HMAC-based CSRF token generation and validation.
// Tokens are self-contained: nonce:timestamp:signature, with configurable expiry.
type CSRFProtection struct {
	signingKey []byte
	ttl        time.Duration
}

// NewCSRFProtection creates a new CSRF protection instance
func NewCSRFProtection(signingKey []byte, ttl time.Duration) CSRFProtection {
	return CSRFProtection{
		signingKey: signingKey,
		ttl:        ttl,
	}
}

// Generate creates a new CSRF token
func (c *CSRFProtection) Generate() (string, error) {
	nonce, err := GenerateSecureToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	data := nonce + ":" + timestamp
	signature := SignData(data, c.signingKey)

	return fmt.Sprintf("%s:%s:%s", nonce, timestamp, signature), nil
}

// Validate checks if a CSRF token is valid and not expired
func (c *CSRFProtection) Validate(token string) bool {
	parts := strings.SplitN(token, ":", 3)
	if len(parts) != 3 {
		return false
	}

	nonce := parts[0]
	timestampStr := parts[1]
	signature := parts[2]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}

	if time.Since(time.Unix(timestamp, 0)) > c.ttl {
		return false
	}

	data := nonce + ":" + timestampStr
	return ValidateSignedData(data, signature, c.signingKey)
}
