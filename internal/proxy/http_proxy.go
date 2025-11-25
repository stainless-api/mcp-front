package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/executiontoken"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/storage"
)

// ErrPathNotAllowed is returned when a request path is not in the allowlist
var ErrPathNotAllowed = errors.New("path not allowed")

// Config represents configuration for a proxied service
type Config struct {
	ServiceName  string
	BaseURL      string
	Timeout      time.Duration
	DefaultPaths []string // Default allowed paths if session doesn't specify
}

// HTTPProxy handles HTTP proxying with token swapping and session management
type HTTPProxy struct {
	storage        storage.Storage
	tokenValidator *executiontoken.Validator
	proxyConfigs   map[string]*Config
	httpClient     *http.Client
}

// RequestContext contains validated request context
type RequestContext struct {
	Session     *storage.ExecutionSession
	ProxyConfig *Config
	UserToken   *storage.StoredToken
	TargetPath  string
}

// NewHTTPProxy creates a new HTTP proxy
func NewHTTPProxy(
	storage storage.Storage,
	tokenValidator *executiontoken.Validator,
	proxyConfigs map[string]*Config,
	timeout time.Duration,
) *HTTPProxy {
	return &HTTPProxy{
		storage:        storage,
		tokenValidator: tokenValidator,
		proxyConfigs:   proxyConfigs,
		httpClient: &http.Client{
			Timeout: timeout,
			// Don't follow redirects automatically
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ServeHTTP handles proxy requests
// URL format: /proxy/{service}/{path}
// Example: /proxy/datadog/api/v1/metrics
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	// Validate request and build context
	reqCtx, err := p.validateRequest(r)
	if err != nil {
		log.LogErrorWithFields("execution_proxy", "Request validation failed", map[string]any{
			"error":  err.Error(),
			"path":   r.URL.Path,
			"method": r.Method,
		})
		// Use 403 Forbidden for path not allowed, 401 Unauthorized for other auth issues
		if errors.Is(err, ErrPathNotAllowed) {
			jsonwriter.WriteForbidden(w, err.Error())
		} else {
			jsonwriter.WriteUnauthorized(w, err.Error())
		}
		return
	}

	// Automatically extend session (hybrid heartbeat approach)
	if err := p.storage.RecordSessionActivity(ctx, reqCtx.Session.SessionID); err != nil {
		log.LogError("Failed to record session activity: %v", err)
		// Don't fail the request, just log the error
	}

	// Proxy the request
	if err := p.proxyRequest(ctx, w, r, reqCtx); err != nil {
		log.LogErrorWithFields("execution_proxy", "Proxy request failed", map[string]any{
			"error":        err.Error(),
			"service":      reqCtx.Session.TargetService,
			"execution_id": reqCtx.Session.ExecutionID,
			"user":         reqCtx.Session.UserEmail,
			"session_id":   reqCtx.Session.SessionID,
		})
		// Error already written to response
		return
	}

	log.LogInfoWithFields("execution_proxy", "Request proxied successfully", map[string]any{
		"session_id":   reqCtx.Session.SessionID,
		"execution_id": reqCtx.Session.ExecutionID,
		"user":         reqCtx.Session.UserEmail,
		"service":      reqCtx.Session.TargetService,
		"method":       r.Method,
		"path":         reqCtx.TargetPath,
		"duration_ms":  time.Since(start).Milliseconds(),
	})
}

// validateRequest validates the request and extracts context
func (p *HTTPProxy) validateRequest(r *http.Request) (*RequestContext, error) {
	ctx := r.Context()

	// Extract bearer token from Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.Split(auth, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	token := parts[1]

	// Validate execution token (lightweight - just session_id)
	claims, err := p.tokenValidator.Validate(token)
	if err != nil {
		return nil, fmt.Errorf("invalid execution token: %w", err)
	}

	// Get session from storage
	session, err := p.storage.GetExecutionSession(ctx, claims.SessionID)
	if err != nil {
		if err == storage.ErrSessionNotFound {
			return nil, fmt.Errorf("session not found or expired")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Check if session has expired
	if session.IsExpired() {
		return nil, fmt.Errorf("session has expired")
	}

	// Extract service name and target path from URL
	// Expected format: /proxy/{service}/{path}
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")
	pathParts := strings.SplitN(path, "/", 2)
	if len(pathParts) < 1 || pathParts[0] == "" {
		return nil, fmt.Errorf("invalid proxy URL format, expected /proxy/{service}/{path}")
	}

	serviceName := pathParts[0]
	targetPath := "/"
	if len(pathParts) > 1 {
		targetPath = "/" + pathParts[1]
	}

	// Verify service matches session
	if session.TargetService != serviceName {
		return nil, fmt.Errorf("token not valid for service %s (session is for %s)", serviceName, session.TargetService)
	}

	// Get proxy configuration for service
	proxyConfig, ok := p.proxyConfigs[serviceName]
	if !ok {
		return nil, fmt.Errorf("service %s not configured for proxying", serviceName)
	}

	// Validate path against allowlist
	allowedPaths := session.AllowedPaths
	if len(allowedPaths) == 0 {
		// Use default paths from config
		allowedPaths = proxyConfig.DefaultPaths
	}

	// Always validate paths (fail-closed if no patterns specified)
	pathMatcher := NewPathMatcher(allowedPaths)
	if !pathMatcher.IsAllowed(targetPath) {
		return nil, fmt.Errorf("%w: %s", ErrPathNotAllowed, targetPath)
	}

	// Retrieve user's token for the target service
	userToken, err := p.storage.GetUserToken(ctx, session.UserEmail, serviceName)
	if err != nil {
		return nil, fmt.Errorf("user credentials not found for service %s: %w", serviceName, err)
	}

	return &RequestContext{
		Session:     session,
		ProxyConfig: proxyConfig,
		UserToken:   userToken,
		TargetPath:  targetPath,
	}, nil
}

// proxyRequest proxies the request to the target service
func (p *HTTPProxy) proxyRequest(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	reqCtx *RequestContext,
) error {
	// Build upstream URL
	upstreamURL := reqCtx.ProxyConfig.BaseURL + reqCtx.TargetPath
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	// Create upstream request
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL, r.Body)
	if err != nil {
		jsonwriter.WriteInternalServerError(w, "Failed to create upstream request")
		return fmt.Errorf("failed to create upstream request: %w", err)
	}

	// Copy headers from original request, excluding hop-by-hop and auth headers
	copyRequestHeaders(upstreamReq.Header, r.Header)

	// Swap execution token for real user credentials
	if reqCtx.UserToken.Type == storage.TokenTypeOAuth {
		upstreamReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", reqCtx.UserToken.OAuthData.AccessToken))
	} else {
		upstreamReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", reqCtx.UserToken.Value))
	}

	// Make upstream request
	upstreamResp, err := p.httpClient.Do(upstreamReq)
	if err != nil {
		jsonwriter.WriteInternalServerError(w, "Failed to reach upstream service")
		return fmt.Errorf("upstream request failed: %w", err)
	}
	defer upstreamResp.Body.Close()

	// Copy response headers
	copyResponseHeaders(w.Header(), upstreamResp.Header)

	// Write status code
	w.WriteHeader(upstreamResp.StatusCode)

	// Stream response body
	if _, err := io.Copy(w, upstreamResp.Body); err != nil {
		return fmt.Errorf("failed to copy response body: %w", err)
	}

	return nil
}

// copyRequestHeaders copies headers from src to dst, excluding certain headers
func copyRequestHeaders(dst, src http.Header) {
	excludeHeaders := map[string]bool{
		"authorization":       true, // We'll add our own
		"connection":          true,
		"keep-alive":          true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"te":                  true,
		"trailer":             true,
		"transfer-encoding":   true,
		"upgrade":             true,
	}

	for key, values := range src {
		if excludeHeaders[strings.ToLower(key)] {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// copyResponseHeaders copies headers from src to dst
func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
