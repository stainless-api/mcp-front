package config

import (
	"encoding/json"
	"fmt"
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
				secrets := []struct {
					name     string
					required bool
				}{
					{"googleClientSecret", true},
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
	if oauth.GoogleClientID == "" {
		return fmt.Errorf("googleClientId is required")
	}
	if oauth.GoogleClientSecret == "" {
		return fmt.Errorf("googleClientSecret is required")
	}
	if oauth.GoogleRedirectURI == "" {
		return fmt.Errorf("googleRedirectUri is required")
	}
	if len(oauth.JWTSecret) < 32 {
		return fmt.Errorf("jwtSecret must be at least 32 characters (got %d). Generate with: openssl rand -base64 32", len(oauth.JWTSecret))
	}
	if len(oauth.EncryptionKey) != 32 {
		return fmt.Errorf("encryptionKey must be exactly 32 characters (got %d). Generate with: openssl rand -base64 32 | head -c 32", len(oauth.EncryptionKey))
	}
	if len(oauth.AllowedDomains) == 0 {
		return fmt.Errorf("at least one allowed domain is required")
	}
	if oauth.Storage == "firestore" {
		if oauth.GCPProject == "" {
			return fmt.Errorf("gcpProject is required when using firestore storage")
		}
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
