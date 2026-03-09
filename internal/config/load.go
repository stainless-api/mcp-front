package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/stainless-api/mcp-front/internal/log"
)

var validServerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func isValidServerName(name string) bool {
	return validServerNameRe.MatchString(name)
}

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

	ResolveDefaults(&config)

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

// ResolveDefaults fills in default values that depend on the full config.
// This is pure transformation — no validation. Must be called before ValidateConfig.
func ResolveDefaults(config *Config) {
	// Collect servers eligible for aggregate defaults: non-aggregate,
	// non-inline (inline servers have no network transport).
	eligibleNames := make([]string, 0)
	for name, server := range config.MCPServers {
		if !server.IsAggregate() && server.TransportType != MCPClientTypeInline {
			eligibleNames = append(eligibleNames, name)
		}
	}
	sort.Strings(eligibleNames)

	for _, server := range config.MCPServers {
		if server.IsAggregate() && server.Servers == nil {
			serversCopy := make([]string, len(eligibleNames))
			copy(serversCopy, eligibleNames)
			server.Servers = serversCopy
		}
	}
}

// ValidateConfig validates the resolved configuration.
// ResolveDefaults must be called first to fill in computed defaults.
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

	aggregateNames := make(map[string]bool)
	for name, server := range config.MCPServers {
		if server.IsAggregate() {
			aggregateNames[name] = true
		}
	}

	for name, server := range config.MCPServers {
		if !isValidServerName(name) {
			return fmt.Errorf("server name '%s' is invalid (must start with alphanumeric, then alphanumeric/underscore/hyphen only)", name)
		}

		if err := validateMCPServer(name, server); err != nil {
			return err
		}

		if server.IsAggregate() {
			if len(server.Servers) == 0 {
				return fmt.Errorf("aggregate server '%s' has no servers (configure servers list or add non-aggregate servers)", name)
			}
			delimiter := server.Delimiter
			if delimiter == "" {
				delimiter = DefaultDelimiter
			}
			seen := make(map[string]bool, len(server.Servers))
			for _, ref := range server.Servers {
				if seen[ref] {
					return fmt.Errorf("aggregate server '%s' has duplicate reference '%s'", name, ref)
				}
				seen[ref] = true
				if ref == name {
					return fmt.Errorf("aggregate server '%s' cannot reference itself", name)
				}
				if aggregateNames[ref] {
					return fmt.Errorf("aggregate server '%s' cannot reference another aggregate '%s'", name, ref)
				}
				refServer, exists := config.MCPServers[ref]
				if !exists {
					return fmt.Errorf("aggregate server '%s' references nonexistent server '%s'", name, ref)
				}
				if refServer.TransportType == MCPClientTypeInline {
					return fmt.Errorf("aggregate server '%s' cannot reference inline server '%s' (inline servers have no network transport)", name, ref)
				}
				if strings.Contains(ref, delimiter) {
					return fmt.Errorf("aggregate server '%s': backend name '%s' contains the namespace delimiter '%s'", name, ref, delimiter)
				}
				if refServer.TransportType == MCPClientTypeStdio {
					log.LogWarnWithFields("config", "Aggregate references stdio backend — this spawns a long-lived process per user", map[string]any{
						"aggregate": name,
						"backend":   ref,
					})
				}
			}
			if server.Discovery.Timeout >= server.Discovery.CacheTTL {
				log.LogWarnWithFields("config", "Discovery timeout >= cacheTTL: discovery may not complete before cache expires", map[string]any{
					"aggregate": name,
					"timeout":   server.Discovery.Timeout,
					"cacheTTL":  server.Discovery.CacheTTL,
				})
			}
		}

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
	if oauth.Storage != "" && oauth.Storage != "memory" && oauth.EncryptionKey == "" {
		return fmt.Errorf("encryptionKey is required when using %s storage", oauth.Storage)
	}
	if oauth.EncryptionKey != "" && len(oauth.EncryptionKey) != 32 {
		return fmt.Errorf("encryptionKey must be exactly 32 bytes (got %d). Generate with: openssl rand -base64 24", len(oauth.EncryptionKey))
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
	if server.IsAggregate() {
		if server.TransportType != MCPClientTypeSSE && server.TransportType != MCPClientTypeStreamable {
			return fmt.Errorf("aggregate server %s must use 'sse' or 'streamable-http' transport, got '%s'", name, server.TransportType)
		}
		if server.Discovery == nil {
			return fmt.Errorf("aggregate server %s is missing discovery configuration", name)
		}
		return nil
	}

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

	// Validate tool filter configuration
	if err := validateToolFilter(name, server); err != nil {
		return err
	}

	return nil
}

func validateToolFilter(name string, server *MCPClientConfig) error {
	if server.Options == nil || server.Options.ToolFilter == nil {
		return nil
	}
	filter := server.Options.ToolFilter
	if len(filter.List) > 0 && filter.Mode == "" {
		return fmt.Errorf("server %s has toolFilter list but no mode (must specify 'allow' or 'block')", name)
	}
	if filter.Mode != "" {
		mode := ToolFilterMode(strings.ToLower(string(filter.Mode)))
		if mode != ToolFilterModeAllow && mode != ToolFilterModeBlock {
			return fmt.Errorf("server %s has invalid toolFilter mode '%s' (must be 'allow' or 'block')", name, filter.Mode)
		}
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
