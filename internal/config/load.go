package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/dgellow/mcp-front/internal/log"
)

// Load loads and processes the config with immediate env var resolution
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config file: %w", err)
	}

	var rawConfig map[string]any
	if err := json.Unmarshal(data, &rawConfig); err != nil {
		return Config{}, fmt.Errorf("parsing config JSON: %w", err)
	}

	version, ok := rawConfig["version"].(string)
	if !ok {
		return Config{}, fmt.Errorf("config version is required")
	}
	if !strings.HasPrefix(version, "v0.0.1-DEV_EDITION") {
		return Config{}, fmt.Errorf("unsupported config version: %s", version)
	}

	if err := validateRawConfig(rawConfig); err != nil {
		return Config{}, fmt.Errorf("config validation failed: %w", err)
	}

	// Parse directly into typed Config struct
	// The custom UnmarshalJSON methods will resolve env vars immediately
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}

	// Extract base path from baseURL
	if err := extractBasePath(&config); err != nil {
		return Config{}, fmt.Errorf("extracting base path: %w", err)
	}

	if err := ValidateConfig(&config); err != nil {
		return Config{}, fmt.Errorf("config validation failed: %w", err)
	}

	return config, nil
}

// validateRawConfig validates the config structure before environment resolution
func validateRawConfig(rawConfig map[string]any) error {
	if proxy, ok := rawConfig["proxy"].(map[string]any); ok {
		if auth, ok := proxy["auth"].(map[string]any); ok {
			if kind, ok := auth["kind"].(string); ok && kind == "oauth" {
				// Validate top-level auth secrets
				secrets := []struct {
					name     string
					required bool
				}{
					{"jwtSecret", true},
					{"encryptionKey", true}, // Always required for OAuth
				}

				for _, secret := range secrets {
					if value, exists := auth[secret.name]; exists {
						// Check if it's a string (bad) or a map (good - env ref)
						if _, isString := value.(string); isString {
							return fmt.Errorf("%s must use environment variable reference for security", secret.name)
						}
						// Verify it's an env ref
						if refMap, isMap := value.(map[string]any); isMap {
							if _, hasEnv := refMap["$env"]; !hasEnv {
								return fmt.Errorf("%s must use {\"$env\": \"VAR_NAME\"} format", secret.name)
							}
						}
					} else if secret.required {
						// For encryptionKey, only required if not using memory storage
						if secret.name == "encryptionKey" {
							if storage, ok := auth["storage"].(string); ok && storage != "memory" && storage != "" {
								return fmt.Errorf("%s is required when using %s storage", secret.name, storage)
							}
						}
					}
				}

				// Validate IDP secret (clientSecret must be env ref)
				if idp, ok := auth["idp"].(map[string]any); ok {
					if clientSecret, exists := idp["clientSecret"]; exists {
						if _, isString := clientSecret.(string); isString {
							return fmt.Errorf("idp.clientSecret must use environment variable reference for security")
						}
						if refMap, isMap := clientSecret.(map[string]any); isMap {
							if _, hasEnv := refMap["$env"]; !hasEnv {
								return fmt.Errorf("idp.clientSecret must use {\"$env\": \"VAR_NAME\"} format")
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// ValidateConfig validates the resolved configuration
func ValidateConfig(config *Config) error {
	if config.Proxy.BaseURL == "" {
		return fmt.Errorf("proxy.baseURL is required")
	}
	if config.Proxy.Addr == "" {
		return fmt.Errorf("proxy.addr is required")
	}

	if oauth := config.Proxy.Auth; oauth != nil {
		if err := validateOAuthConfig(oauth); err != nil {
			return fmt.Errorf("oauth config: %w", err)
		}
	}

	hasOAuth := config.Proxy.Auth != nil

	for name, server := range config.MCPServers {
		if err := validateMCPServer(name, server); err != nil {
			return err
		}

		// Validate that user tokens require OAuth
		if server.RequiresUserToken && !hasOAuth {
			return fmt.Errorf("server %s requires user tokens but OAuth is not configured - user tokens require OAuth authentication", name)
		}
	}

	// Validate proxy session configuration
	if config.Proxy.Sessions != nil {
		if config.Proxy.Sessions.Timeout < 0 {
			return fmt.Errorf("proxy.sessions.timeout cannot be negative")
		}
		if config.Proxy.Sessions.CleanupInterval < 0 {
			return fmt.Errorf("proxy.sessions.cleanupInterval cannot be negative")
		}
		if config.Proxy.Sessions.Timeout > 0 && config.Proxy.Sessions.CleanupInterval > config.Proxy.Sessions.Timeout {
			log.LogWarn("Session cleanup interval is greater than session timeout")
		}
		if config.Proxy.Sessions.MaxPerUser < 0 {
			return fmt.Errorf("proxy.sessions.maxPerUser cannot be negative")
		}
		if config.Proxy.Sessions.MaxPerUser == 0 {
			log.LogWarn("Session maxPerUser is 0 (unlimited) - this may allow resource exhaustion")
		}
	}

	return nil
}

func validateOAuthConfig(oauth *OAuthAuthConfig) error {
	if oauth.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}

	// Validate IDP configuration
	if oauth.IDP.Provider == "" {
		return fmt.Errorf("idp.provider is required (google, azure, github, or oidc)")
	}
	if oauth.IDP.ClientID == "" {
		return fmt.Errorf("idp.clientId is required")
	}
	if oauth.IDP.ClientSecret == "" {
		return fmt.Errorf("idp.clientSecret is required")
	}
	if oauth.IDP.RedirectURI == "" {
		return fmt.Errorf("idp.redirectUri is required")
	}

	// Provider-specific validation
	switch oauth.IDP.Provider {
	case "google":
		// No additional validation needed
	case "azure":
		if oauth.IDP.TenantID == "" {
			return fmt.Errorf("idp.tenantId is required for Azure AD")
		}
	case "github":
		// No additional validation needed
	case "oidc":
		// Either discoveryUrl or all manual endpoints required
		if oauth.IDP.DiscoveryURL == "" {
			if oauth.IDP.AuthorizationURL == "" || oauth.IDP.TokenURL == "" || oauth.IDP.UserInfoURL == "" {
				return fmt.Errorf("idp.discoveryUrl or all of (authorizationUrl, tokenUrl, userInfoUrl) required for OIDC")
			}
		}
	default:
		return fmt.Errorf("unsupported idp.provider: %s (must be google, azure, github, or oidc)", oauth.IDP.Provider)
	}

	if len(oauth.JWTSecret) < 32 {
		return fmt.Errorf("jwtSecret must be at least 32 characters (got %d). Generate with: openssl rand -base64 32", len(oauth.JWTSecret))
	}
	if len(oauth.EncryptionKey) != 32 {
		return fmt.Errorf("encryptionKey must be exactly 32 characters (got %d). Generate with: openssl rand -base64 32 | head -c 32", len(oauth.EncryptionKey))
	}

	// Domain or org validation - at least one access control mechanism required
	if len(oauth.AllowedDomains) == 0 && len(oauth.IDP.AllowedOrgs) == 0 {
		return fmt.Errorf("at least one of allowedDomains or idp.allowedOrgs is required")
	}

	if oauth.Storage == "firestore" {
		if oauth.GCPProject == "" {
			return fmt.Errorf("gcpProject is required when using firestore storage")
		}
	}
	if oauth.TokenTTL <= 0 {
		return fmt.Errorf("tokenTtl must be positive")
	}
	if oauth.RefreshTokenTTL <= 0 {
		return fmt.Errorf("refreshTokenTtl must be positive")
	}
	return nil
}

func validateMCPServer(name string, server *MCPClientConfig) error {
	// Transport type is required
	if server.TransportType == "" {
		return fmt.Errorf("server %s must specify transportType (stdio, sse, streamable-http, or inline)", name)
	}

	// Validate based on transport type
	switch server.TransportType {
	case MCPClientTypeStdio:
		if server.Command == "" {
			return fmt.Errorf("server %s with stdio transport must have command", name)
		}
		if server.URL != "" {
			return fmt.Errorf("server %s with stdio transport cannot have url", name)
		}
	case MCPClientTypeSSE, MCPClientTypeStreamable:
		if server.URL == "" {
			return fmt.Errorf("server %s with %s transport must have url", name, server.TransportType)
		}
		if server.Command != "" {
			return fmt.Errorf("server %s with %s transport cannot have command", name, server.TransportType)
		}
	case MCPClientTypeInline:
		if len(server.InlineConfig) == 0 {
			return fmt.Errorf("server %s with inline transport must have inline configuration", name)
		}
		if server.Command != "" || server.URL != "" {
			return fmt.Errorf("server %s with inline transport cannot have command or url", name)
		}
	default:
		return fmt.Errorf("server %s has invalid transportType: %s", name, server.TransportType)
	}

	// Validate user authentication if required
	if server.RequiresUserToken && server.UserAuthentication == nil {
		return fmt.Errorf("server %s requires user token but has no userAuthentication", name)
	}

	return nil
}

func extractBasePath(config *Config) error {
	u, err := url.Parse(config.Proxy.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid baseURL: %w", err)
	}

	basePath := u.Path
	if basePath == "" {
		basePath = "/"
	}

	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if len(basePath) > 1 && strings.HasSuffix(basePath, "/") {
		basePath = strings.TrimSuffix(basePath, "/")
	}

	config.Proxy.BasePath = basePath

	log.LogInfoWithFields("config", "Extracted base path from baseURL", map[string]any{
		"baseURL":  config.Proxy.BaseURL,
		"basePath": basePath,
	})

	return nil
}
