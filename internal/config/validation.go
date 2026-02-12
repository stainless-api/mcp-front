package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// ValidationResult holds validation errors and warnings
type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

// ValidationError represents a validation issue
type ValidationError struct {
	Path    string
	Message string
}

// IsValid returns true if there are no errors
func (v *ValidationResult) IsValid() bool {
	return len(v.Errors) == 0
}

// ValidateFile validates a config file structure without requiring env vars
func ValidateFile(path string) (*ValidationResult, error) {
	result := &ValidationResult{}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	// Check JSON syntax
	var rawConfig map[string]any
	if err := json.Unmarshal(data, &rawConfig); err != nil {
		result.Errors = append(result.Errors, ValidationError{
			Message: fmt.Sprintf("invalid JSON: %v", err),
		})
		return result, nil
	}

	// Check for bash-style syntax
	checkBashStyleSyntax(rawConfig, "", result)

	// Check version
	version, ok := rawConfig["version"].(string)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "version",
			Message: "version field is required. Hint: Add \"version\": \"v0.0.1-DEV_EDITION\"",
		})
	} else if !strings.HasPrefix(version, "v0.0.1-DEV_EDITION") {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "version",
			Message: fmt.Sprintf("unsupported version '%s' - use 'v0.0.1-DEV_EDITION' or 'v0.0.1-DEV_EDITION-<variant>'", version),
		})
	}

	// Check proxy structure
	validateProxyStructure(rawConfig, result)

	// Check servers structure
	validateServersStructure(rawConfig, result)

	return result, nil
}

// validateProxyStructure checks the proxy configuration structure
func validateProxyStructure(rawConfig map[string]any, result *ValidationResult) {
	proxy, ok := rawConfig["proxy"].(map[string]any)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy",
			Message: "proxy field is required and must be an object",
		})
		return
	}

	// Check required proxy fields
	if _, ok := proxy["baseURL"]; !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.baseURL",
			Message: "baseURL is required. Example: \"https://api.example.com\"",
		})
	}
	if _, ok := proxy["addr"]; !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.addr",
			Message: "addr is required. Example: \":8080\" or \"0.0.0.0:8080\"",
		})
	}

	// Check auth if present
	if auth, ok := proxy["auth"].(map[string]any); ok {
		validateAuthStructure(auth, result)
	}

	// Check sessions configuration if present
	if sessions, ok := proxy["sessions"].(map[string]any); ok {
		validateSessionsConfig(sessions, result)
	}

	// Check admin if present
	if admin, ok := proxy["admin"].(map[string]any); ok {
		validateAdminStructure(admin, result)

		// If admin is enabled, ensure OAuth is configured
		if enabled, ok := admin["enabled"].(bool); ok && enabled {
			hasOAuth := false
			if auth, ok := proxy["auth"].(map[string]any); ok {
				if kind, ok := auth["kind"].(string); ok && kind == "oauth" {
					hasOAuth = true
				}
			}
			if !hasOAuth {
				result.Errors = append(result.Errors, ValidationError{
					Path:    "proxy.admin",
					Message: "admin UI requires OAuth authentication to be configured. Set proxy.auth.kind to 'oauth'",
				})
			}
		}
	}
}

// validateAuthStructure checks auth configuration structure
func validateAuthStructure(auth map[string]any, result *ValidationResult) {
	kind, ok := auth["kind"].(string)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.kind",
			Message: "auth kind is required. Use \"oauth\" for Google OAuth authentication",
		})
		return
	}

	switch kind {
	case "oauth":
		// Check required OAuth fields
		requiredFields := []struct {
			name string
			hint string
		}{
			{"issuer", ""},
			{"jwtSecret", "Hint: Must be at least 32 bytes long for HMAC-SHA256"},
			{"encryptionKey", "Hint: Must be exactly 32 bytes for AES-256-GCM encryption"},
		}
		for _, field := range requiredFields {
			if _, ok := auth[field.name]; !ok {
				msg := fmt.Sprintf("%s is required for OAuth", field.name)
				if field.hint != "" {
					msg += ". " + field.hint
				}
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("proxy.auth.%s", field.name),
					Message: msg,
				})
			}
		}

		// Validate IDP configuration
		idp, hasIDP := auth["idp"].(map[string]any)
		if !hasIDP {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.auth.idp",
				Message: "idp configuration is required for OAuth",
			})
		} else {
			validateIDPStructure(idp, result)
		}

		if origins, ok := auth["allowedOrigins"].([]any); !ok || len(origins) == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.auth.allowedOrigins",
				Message: "at least one allowed origin is required for OAuth (CORS configuration)",
			})
		}
	default:
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.kind",
			Message: fmt.Sprintf("unknown auth kind '%s' - only 'oauth' is supported for proxy auth", kind),
		})
	}
}

// validateIDPStructure checks identity provider configuration
func validateIDPStructure(idp map[string]any, result *ValidationResult) {
	provider, ok := idp["provider"].(string)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.idp.provider",
			Message: "provider is required. Options: google, azure, github, oidc",
		})
		return
	}

	// Check required fields for all providers
	if _, ok := idp["clientId"]; !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.idp.clientId",
			Message: "clientId is required for IDP configuration",
		})
	}
	if _, ok := idp["clientSecret"]; !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.idp.clientSecret",
			Message: "clientSecret is required for IDP configuration",
		})
	}
	if _, ok := idp["redirectUri"]; !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.idp.redirectUri",
			Message: "redirectUri is required for IDP configuration",
		})
	}

	// Provider-specific validation
	switch provider {
	case "google", "github":
		// No additional required fields
	case "azure":
		if _, ok := idp["tenantId"]; !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.auth.idp.tenantId",
				Message: "tenantId is required for Azure AD provider",
			})
		}
	case "oidc":
		// Either discoveryUrl or manual endpoints required
		hasDiscovery := false
		if _, ok := idp["discoveryUrl"]; ok {
			hasDiscovery = true
		}
		if !hasDiscovery {
			// Check for manual endpoints
			requiredEndpoints := []string{"authorizationUrl", "tokenUrl", "userInfoUrl"}
			for _, endpoint := range requiredEndpoints {
				if _, ok := idp[endpoint]; !ok {
					result.Errors = append(result.Errors, ValidationError{
						Path:    "proxy.auth.idp." + endpoint,
						Message: fmt.Sprintf("%s is required for OIDC provider when discoveryUrl is not provided", endpoint),
					})
				}
			}
		}
	default:
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.auth.idp.provider",
			Message: fmt.Sprintf("unknown provider '%s' - supported providers: google, azure, github, oidc", provider),
		})
	}
}

// validateAdminStructure checks admin configuration structure
func validateAdminStructure(admin map[string]any, result *ValidationResult) {
	enabled, ok := admin["enabled"].(bool)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "proxy.admin.enabled",
			Message: "enabled field is required and must be a boolean",
		})
		return
	}

	if enabled {
		// Check adminEmails when enabled
		emails, ok := admin["adminEmails"].([]any)
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.admin.adminEmails",
				Message: "adminEmails is required when admin is enabled",
			})
		} else if len(emails) == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Path:    "proxy.admin.adminEmails",
				Message: "at least one admin email is required when admin is enabled",
			})
		} else {
			// Validate each email is a string
			for i, email := range emails {
				if _, ok := email.(string); !ok {
					result.Errors = append(result.Errors, ValidationError{
						Path:    fmt.Sprintf("proxy.admin.adminEmails[%d]", i),
						Message: fmt.Sprintf("admin email must be a string, got %T - use \"user@example.com\" format", email),
					})
				}
			}
		}

		// Check that OAuth is configured (required for admin functionality)
		// Note: We check this at the parent level since auth is a sibling of admin
	}
}

// validateServersStructure checks MCP servers configuration
func validateServersStructure(rawConfig map[string]any, result *ValidationResult) {
	servers, ok := rawConfig["mcpServers"].(map[string]any)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    "mcpServers",
			Message: "mcpServers field is required and must be an object",
		})
		return
	}

	hasOAuth := false
	if proxy, ok := rawConfig["proxy"].(map[string]any); ok {
		if auth, ok := proxy["auth"].(map[string]any); ok {
			if kind, ok := auth["kind"].(string); ok && kind == "oauth" {
				hasOAuth = true
			}
		}
	}

	for name, server := range servers {
		srv, ok := server.(map[string]any)
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s", name),
				Message: "server must be an object",
			})
			continue
		}

		// Check transport type
		transportType, ok := srv["transportType"].(string)
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s.transportType", name),
				Message: "transportType is required. Options: stdio, sse, streamable-http, inline",
			})
			continue
		}

		// Validate based on transport type
		switch transportType {
		case "stdio":
			if _, ok := srv["command"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.command", name),
					Message: "command is required for stdio transport. Example: [\"npx\", \"-y\", \"@your/mcp-server\"]",
				})
			}
		case "sse", "streamable-http":
			if _, ok := srv["url"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.url", name),
					Message: fmt.Sprintf("url is required for %s transport", transportType),
				})
			}
		case "inline":
			if _, ok := srv["inline"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.inline", name),
					Message: "inline configuration is required for inline transport",
				})
			}
		default:
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s.transportType", name),
				Message: fmt.Sprintf("invalid transportType '%s' - supported types: stdio, sse, streamable-http, inline", transportType),
			})
		}

		// Check user token requirements
		if requiresToken, ok := srv["requiresUserToken"].(bool); ok && requiresToken {
			if !hasOAuth {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.requiresUserToken", name),
					Message: "server requires user token but OAuth is not configured. Hint: User tokens require OAuth authentication - set proxy.auth.kind to 'oauth'",
				})
			}
			if userAuth, ok := srv["userAuthentication"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.userAuthentication", name),
					Message: "userAuthentication is required when requiresUserToken is true. Hint: Add userAuthentication with type, displayName and instructions",
				})
			} else {
				validateUserAuthentication(userAuth, fmt.Sprintf("mcpServers.%s.userAuthentication", name), result)
			}
		}

		// Check service auth configuration
		if serviceAuths, ok := srv["serviceAuths"].([]any); ok {
			requiresUserToken := false
			if requiresToken, ok := srv["requiresUserToken"].(bool); ok {
				requiresUserToken = requiresToken
			}
			validateServiceAuths(serviceAuths, name, requiresUserToken, result)
		}
	}
}

// validateServiceAuths validates service authentication configuration
func validateServiceAuths(serviceAuths []any, serverName string, requiresUserToken bool, result *ValidationResult) {
	for i, authInterface := range serviceAuths {
		auth, ok := authInterface.(map[string]any)
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s.serviceAuths[%d]", serverName, i),
				Message: "service auth must be an object",
			})
			continue
		}

		authType, ok := auth["type"].(string)
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s.serviceAuths[%d].type", serverName, i),
				Message: "service auth type is required. Options: basic, bearer",
			})
			continue
		}

		switch authType {
		case "basic":
			if _, ok := auth["username"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.serviceAuths[%d].username", serverName, i),
					Message: "username is required for basic auth",
				})
			}
			if _, ok := auth["password"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.serviceAuths[%d].password", serverName, i),
					Message: "password is required for basic auth",
				})
			} else {
				// Validate password uses env var reference
				validatePasswordReference(auth["password"], fmt.Sprintf("mcpServers.%s.serviceAuths[%d].password", serverName, i), result)
			}
		case "bearer":
			tokens, ok := auth["tokens"].([]any)
			if !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.serviceAuths[%d].tokens", serverName, i),
					Message: "tokens array is required for bearer auth",
				})
			} else if len(tokens) == 0 {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.serviceAuths[%d].tokens", serverName, i),
					Message: "at least one token is required for bearer auth",
				})
			}
		default:
			result.Errors = append(result.Errors, ValidationError{
				Path:    fmt.Sprintf("mcpServers.%s.serviceAuths[%d].type", serverName, i),
				Message: fmt.Sprintf("unknown service auth type '%s' - supported types: basic, bearer", authType),
			})
		}

		// If server requires user token, validate that service auth provides one
		if requiresUserToken {
			if _, ok := auth["userToken"]; !ok {
				result.Errors = append(result.Errors, ValidationError{
					Path:    fmt.Sprintf("mcpServers.%s.serviceAuths[%d].userToken", serverName, i),
					Message: "userToken is required when server has requiresUserToken: true. Hint: Use {\"$userToken\": \"{{token}}\"} to inject user's token",
				})
			} else {
				validateUserTokenReference(auth["userToken"], fmt.Sprintf("mcpServers.%s.serviceAuths[%d].userToken", serverName, i), result)
			}
		}
	}
}

// validateEnvVarReference validates that a field uses proper env var reference format
func validateEnvVarReference(value any, fieldName, path string) *ValidationError {
	switch v := value.(type) {
	case string:
		// Check if it looks like a bash-style env var
		bashStyleRegex := regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)\}?`)
		if matches := bashStyleRegex.FindStringSubmatch(v); len(matches) > 1 {
			varName := matches[1]
			return &ValidationError{
				Path:    path,
				Message: fmt.Sprintf("found bash-style syntax '%s' - use {\"$env\": \"%s\"} instead. Hint: JSON syntax prevents accidental shell expansion and ensures security", v, varName),
			}
		}
		// Plain string value
		return &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("%s must use environment variable reference {\"$env\": \"YOUR_ENV_VAR\"} instead of plain text '%s'. Hint: This prevents secrets from being stored in config files", fieldName, v),
		}
	case map[string]any:
		if _, hasEnv := v["$env"]; !hasEnv {
			return &ValidationError{
				Path:    path,
				Message: fmt.Sprintf("%s must use {\"$env\": \"YOUR_ENV_VAR\"} format, not %v", fieldName, v),
			}
		}
		// Valid env reference
		return nil
	default:
		return &ValidationError{
			Path:    path,
			Message: fmt.Sprintf("%s must be an environment variable reference {\"$env\": \"YOUR_ENV_VAR\"}, not %T", fieldName, value),
		}
	}
}

// validatePasswordReference validates that password uses env var reference
func validatePasswordReference(password any, path string, result *ValidationResult) {
	if err := validateEnvVarReference(password, "password", path); err != nil {
		result.Errors = append(result.Errors, *err)
	}
}

// validateUserTokenReference validates that userToken uses proper reference format
func validateUserTokenReference(userToken any, path string, result *ValidationResult) {
	switch v := userToken.(type) {
	case string:
		// Plain string is not allowed for userToken
		result.Errors = append(result.Errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("userToken must use {\"$userToken\": \"{{token}}\"} format instead of plain text '%s'. Hint: This injects the user's authenticated token at runtime", v),
		})
	case map[string]any:
		if _, hasUserToken := v["$userToken"]; !hasUserToken {
			// Check if they're trying to use env var syntax
			if _, hasEnv := v["$env"]; hasEnv {
				result.Errors = append(result.Errors, ValidationError{
					Path:    path,
					Message: "userToken cannot use {\"$env\": \"...\"} syntax - use {\"$userToken\": \"{{token}}\"} to inject user's authenticated token",
				})
			} else {
				result.Errors = append(result.Errors, ValidationError{
					Path:    path,
					Message: fmt.Sprintf("userToken must use {\"$userToken\": \"{{token}}\"} format, not %v", v),
				})
			}
		}
		// Valid userToken reference
	default:
		result.Errors = append(result.Errors, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("userToken must be a reference object {\"$userToken\": \"{{token}}\"}, not %T", userToken),
		})
	}
}

// validateUserAuthentication validates user authentication configuration
func validateUserAuthentication(userAuth any, path string, result *ValidationResult) {
	auth, ok := userAuth.(map[string]any)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    path,
			Message: "userAuthentication must be an object",
		})
		return
	}

	// Check required type field
	authType, ok := auth["type"].(string)
	if !ok {
		result.Errors = append(result.Errors, ValidationError{
			Path:    path + ".type",
			Message: "type is required. Options: oauth (for automated OAuth flow) or manual (for user-provided tokens)",
		})
		return
	}

	// Validate based on type
	switch authType {
	case "oauth":
		validateOAuthServiceConfig(auth, path, result)
	case "manual":
		// Manual requires displayName and instructions
		if _, ok := auth["displayName"]; !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    path + ".displayName",
				Message: "displayName is required for manual authentication. Example: \"GitHub Personal Access Token\"",
			})
		}
		if _, ok := auth["instructions"]; !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    path + ".instructions",
				Message: "instructions are required for manual authentication. Example: \"Create a token at https://github.com/settings/tokens\"",
			})
		}
	default:
		result.Errors = append(result.Errors, ValidationError{
			Path:    path + ".type",
			Message: fmt.Sprintf("invalid authentication type '%s' - must be 'oauth' or 'manual'", authType),
		})
	}
}

// validateOAuthServiceConfig validates OAuth service configuration
func validateOAuthServiceConfig(oauth map[string]any, path string, result *ValidationResult) {
	// Check required fields
	requiredFields := []string{"clientId", "authorizationUrl", "tokenUrl", "scopes"}
	for _, field := range requiredFields {
		if _, ok := oauth[field]; !ok {
			result.Errors = append(result.Errors, ValidationError{
				Path:    path + "." + field,
				Message: fmt.Sprintf("%s is required for OAuth configuration", field),
			})
		}
	}

	// Validate scopes is an array
	if scopes, ok := oauth["scopes"].([]any); ok {
		if len(scopes) == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Path:    path + ".scopes",
				Message: "at least one scope is required",
			})
		}
	} else {
		result.Errors = append(result.Errors, ValidationError{
			Path:    path + ".scopes",
			Message: "scopes must be an array",
		})
	}

	// Check client secret uses env var
	if clientSecret, ok := oauth["clientSecret"]; ok {
		validateSecretReference(clientSecret, path+".clientSecret", result)
	} else {
		result.Errors = append(result.Errors, ValidationError{
			Path:    path + ".clientSecret",
			Message: "clientSecret is required for OAuth configuration",
		})
	}
}

// validateSecretReference validates that secret uses env var reference
func validateSecretReference(secret any, path string, result *ValidationResult) {
	if err := validateEnvVarReference(secret, "clientSecret", path); err != nil {
		result.Errors = append(result.Errors, *err)
	}
}

// checkBashStyleSyntax recursively checks for bash-style env var syntax
func checkBashStyleSyntax(value any, path string, result *ValidationResult) {
	bashStyleRegex := regexp.MustCompile(`\$\{?[A-Z_][A-Z0-9_]*\}?`)

	switch v := value.(type) {
	case string:
		if matches := bashStyleRegex.FindAllString(v, -1); len(matches) > 0 {
			for _, match := range matches {
				varName := strings.Trim(match, "${}")
				result.Warnings = append(result.Warnings, ValidationError{
					Path:    path,
					Message: fmt.Sprintf("found bash-style syntax '%s' - use {\"$env\": \"%s\"} instead. Hint: JSON syntax prevents accidental shell expansion in scripts/CI and ensures unambiguous parsing", match, varName),
				})
			}
		}
	case map[string]any:
		// Skip if this is already an env/userToken ref
		if _, hasEnv := v["$env"]; hasEnv {
			return
		}
		if _, hasUserToken := v["$userToken"]; hasUserToken {
			return
		}

		for key, val := range v {
			newPath := path
			if newPath == "" {
				newPath = key
			} else {
				newPath = path + "." + key
			}
			checkBashStyleSyntax(val, newPath, result)
		}
	case []any:
		for i, item := range v {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			checkBashStyleSyntax(item, newPath, result)
		}
	}
}

// validateSessionsConfig checks session management configuration
func validateSessionsConfig(sessions map[string]any, result *ValidationResult) {
	// Parse timeout and cleanupInterval if both present
	var timeoutStr, cleanupStr string
	var hasTimeout, hasCleanup bool

	if t, ok := sessions["timeout"].(string); ok {
		timeoutStr = t
		hasTimeout = true
	}

	if c, ok := sessions["cleanupInterval"].(string); ok {
		cleanupStr = c
		hasCleanup = true
	}

	// Only validate if both are present
	if hasTimeout && hasCleanup {
		timeoutDur, err1 := time.ParseDuration(timeoutStr)
		cleanupDur, err2 := time.ParseDuration(cleanupStr)

		if err1 == nil && err2 == nil {
			if cleanupDur > timeoutDur {
				result.Warnings = append(result.Warnings, ValidationError{
					Path: "proxy.sessions",
					Message: fmt.Sprintf(
						"cleanupInterval (%s) is longer than timeout (%s). Expired sessions will remain in memory until cleanup runs.",
						cleanupStr, timeoutStr,
					),
				})
			}
		}
	}
}
