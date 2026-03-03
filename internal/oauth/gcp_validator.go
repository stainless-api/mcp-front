package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/dgellow/mcp-front/internal/log"
)

const (
	defaultTokenInfoURL = "https://oauth2.googleapis.com/tokeninfo"
	maxCacheTTL         = 5 * time.Minute
)

type cachedTokenInfo struct {
	email     string
	expiresAt time.Time
}

type GCPAccessTokenValidator struct {
	tokenInfoURL string
	httpClient   *http.Client
	cache        sync.Map
}

func NewGCPAccessTokenValidator() *GCPAccessTokenValidator {
	return &GCPAccessTokenValidator{
		tokenInfoURL: defaultTokenInfoURL,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *GCPAccessTokenValidator) Validate(ctx context.Context, token string) (string, error) {
	if cached, ok := v.cache.Load(token); ok {
		info := cached.(*cachedTokenInfo)
		if time.Now().Before(info.expiresAt) {
			return info.email, nil
		}
		v.cache.Delete(token)
	}

	reqURL := v.tokenInfoURL + "?access_token=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating tokeninfo request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("tokeninfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GCP access token validation failed: status %d", resp.StatusCode)
	}

	var result struct {
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		ExpiresIn     string `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing tokeninfo response: %w", err)
	}

	if result.Email == "" {
		return "", fmt.Errorf("GCP access token missing email claim")
	}

	if result.EmailVerified != "true" {
		return "", fmt.Errorf("GCP access token email not verified")
	}

	ttl := maxCacheTTL
	if result.ExpiresIn != "" {
		if expiresInSec, err := strconv.Atoi(result.ExpiresIn); err == nil {
			tokenTTL := time.Duration(expiresInSec) * time.Second
			if tokenTTL < ttl {
				ttl = tokenTTL
			}
		}
	}

	v.cache.Store(token, &cachedTokenInfo{
		email:     result.Email,
		expiresAt: time.Now().Add(ttl),
	})

	log.LogDebugWithFields("gcp_auth", "Access token validated and cached", map[string]any{
		"email": result.Email,
		"ttl":   ttl.String(),
	})

	return result.Email, nil
}
