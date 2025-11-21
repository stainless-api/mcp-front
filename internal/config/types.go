package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

// Secret is a string type that redacts itself when printed
type Secret string

// String implements fmt.Stringer to redact the secret
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "***"
}

// MarshalJSON implements json.Marshaler to prevent secrets in JSON logs
func (s Secret) MarshalJSON() ([]byte, error) {
	if s == "" {
		return json.Marshal("")
	}
	return json.Marshal("***")
}

// MCPClientType represents the transport type for MCP clients
type MCPClientType string

const (
	MCPClientTypeStdio      MCPClientType = "stdio"
	MCPClientTypeSSE        MCPClientType = "sse"
	MCPClientTypeStreamable MCPClientType = "streamable-http"
	MCPClientTypeInline     MCPClientType = "inline"
)

// AuthKind represents the type of authentication
type AuthKind string

const (
	AuthKindOAuth AuthKind = "oauth"
)

// ToolFilterMode for tool filtering
type ToolFilterMode string

const (
	ToolFilterModeAllow ToolFilterMode = "allow"
	ToolFilterModeBlock ToolFilterMode = "block"
)

// ToolFilterConfig configures tool filtering
type ToolFilterConfig struct {
	Mode ToolFilterMode `json:"mode,omitempty"`
	List []string       `json:"list,omitempty"`
}

// Options for MCP client configuration
type Options struct {
	PanicIfInvalid *bool             `json:"panicIfInvalid,omitempty"`
	AuthTokens     []string          `json:"authTokens,omitempty"`
	ToolFilter     *ToolFilterConfig `json:"toolFilter,omitempty"`
}

// ServiceAuthType represents the type of service authentication
type ServiceAuthType string

const (
	ServiceAuthTypeBearer ServiceAuthType = "bearer"
	ServiceAuthTypeBasic  ServiceAuthType = "basic"
)

// UserAuthType represents the type of user authentication
type UserAuthType string

const (
	// UserAuthTypeManual indicates that users manually provide API tokens/keys
	// through the web UI. These tokens are stored encrypted and injected into
	// MCP servers as configured.
	UserAuthTypeManual UserAuthType = "manual"

	// UserAuthTypeOAuth indicates OAuth 2.0 authorization code flow is used.
	// Users click "Connect with X" and are redirected to the service's OAuth
	// consent page. The resulting access tokens are stored, automatically
	// refreshed, and injected into MCP servers.
	UserAuthTypeOAuth UserAuthType = "oauth"
)

// ServiceAuth represents authentication method for service-to-service communication
type ServiceAuth struct {
	Type ServiceAuthType `json:"type"`

	// For basic auth
	Username    string          `json:"username,omitempty"`
	PasswordRaw json.RawMessage `json:"password,omitempty"`

	// For bearer auth
	Tokens []string `json:"tokens,omitempty"`

	// User token to inject when requiresUserToken is true
	UserTokenRaw json.RawMessage `json:"userToken,omitempty"`

	// Computed fields
	HashedPassword Secret `json:"-"` // bcrypt hash for basic auth
	UserToken      Secret `json:"-"` // parsed user token
}

// UserAuthentication represents authentication configuration for end users
type UserAuthentication struct {
	Type        UserAuthType `json:"type"`
	DisplayName string       `json:"displayName"`

	// For OAuth
	ClientIDRaw      json.RawMessage `json:"clientId,omitempty"`
	ClientSecretRaw  json.RawMessage `json:"clientSecret,omitempty"`
	AuthorizationURL string          `json:"authorizationUrl,omitempty"`
	TokenURL         string          `json:"tokenUrl,omitempty"`
	Scopes           []string        `json:"scopes,omitempty"`

	// For Manual
	Instructions string `json:"instructions,omitempty"`
	HelpURL      string `json:"helpUrl,omitempty"`
	Validation   string `json:"validation,omitempty"`

	// Common
	TokenFormat string `json:"tokenFormat,omitempty"`

	// Computed fields
	ClientID        Secret         `json:"-"`
	ClientSecret    Secret         `json:"-"`
	ValidationRegex *regexp.Regexp `json:"-"`
}

// MCPClientConfig represents the configuration for an MCP client after parsing.
//
// Environment variable references using {"$env": "VAR_NAME"} syntax are resolved
// at config load time. This explicit JSON syntax was chosen over bash-like $VAR
// substitution for important security reasons:
//
//  1. Shell Safety: Config files are often manipulated in shell contexts (startup
//     scripts, CI/CD pipelines). Using $VAR could lead to accidental expansion by
//     the shell before the config is parsed.
//
//  2. Unambiguous Intent: {"$env": "X"} clearly indicates this is a reference to
//     be resolved by our application, not a literal string containing $.
//
//  3. Nested Value Safety: If an environment variable value contains $, it won't
//     be accidentally re-expanded.
//
//  4. Type Safety: The JSON structure allows us to validate references at parse
//     time rather than discovering invalid patterns at runtime.
//
// User token references using {"$userToken": "...{{token}}..."} follow the same
// pattern but are resolved at request time with the authenticated user's token.
type MCPClientConfig struct {
	TransportType MCPClientType `json:"transportType,omitempty"`

	// Stdio
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// Track which values need user token substitution
	EnvNeedsToken map[string]bool `json:"-"`
	ArgsNeedToken []bool          `json:"-"`

	// SSE or Streamable HTTP
	URL              string            `json:"url,omitempty"`
	URLNeedsToken    bool              `json:"-"` // Track if URL needs token substitution
	Headers          map[string]string `json:"headers,omitempty"`
	HeadersNeedToken map[string]bool   `json:"-"` // Track which headers need token substitution
	Timeout          time.Duration     `json:"timeout,omitempty"`

	Options *Options `json:"options,omitempty"`

	// User token requirements
	RequiresUserToken  bool                `json:"requiresUserToken,omitempty"`
	UserAuthentication *UserAuthentication `json:"userAuthentication,omitempty"`

	// Service-to-service authentication
	ServiceAuths []ServiceAuth `json:"serviceAuths,omitempty"`

	// Inline MCP server configuration
	InlineConfig json.RawMessage `json:"inline,omitempty"`
}

// SessionConfig represents session management configuration
type SessionConfig struct {
	Timeout         time.Duration
	CleanupInterval time.Duration
	MaxPerUser      int
}

// AdminConfig represents admin UI configuration
type AdminConfig struct {
	Enabled     bool     `json:"enabled"`
	AdminEmails []string `json:"adminEmails"`
}

// OAuthAuthConfig represents OAuth 2.1 configuration with resolved values
type OAuthAuthConfig struct {
	Kind                AuthKind      `json:"kind"`
	Issuer              string        `json:"issuer"`
	GCPProject          string        `json:"gcpProject"`
	AllowedDomains      []string      `json:"allowedDomains"` // For Google OAuth email validation
	AllowedOrigins      []string      `json:"allowedOrigins"` // For CORS validation
	TokenTTL            time.Duration `json:"tokenTtl"`
	Storage             string        `json:"storage"`                       // "memory" or "firestore"
	FirestoreDatabase   string        `json:"firestoreDatabase,omitempty"`   // Optional: Firestore database name
	FirestoreCollection string        `json:"firestoreCollection,omitempty"` // Optional: Firestore collection name
	GoogleClientID      string        `json:"googleClientId"`
	GoogleClientSecret  Secret        `json:"googleClientSecret"`
	GoogleRedirectURI   string        `json:"googleRedirectUri"`
	JWTSecret           Secret        `json:"jwtSecret"`
	EncryptionKey       Secret        `json:"encryptionKey"`
}

// ProxyConfig represents the proxy configuration with resolved values
type ProxyConfig struct {
	BaseURL  string           `json:"baseURL"`
	Addr     string           `json:"addr"`
	Name     string           `json:"name"`
	Auth     *OAuthAuthConfig `json:"auth,omitempty"` // Only OAuth is supported
	Admin    *AdminConfig     `json:"admin,omitempty"`
	Sessions *SessionConfig   `json:"sessions,omitempty"`
}

// Config represents the config structure with resolved values
type Config struct {
	Proxy      ProxyConfig                 `json:"proxy"`
	MCPServers map[string]*MCPClientConfig `json:"mcpServers"`
}

// RawConfigValue represents a value that could be a string, env ref, or user token ref
// This is only used during parsing, not in the final config
type RawConfigValue struct {
	value          string
	needsUserToken bool
}

// ParseConfigValue parses a JSON value that could be a string or reference object
func ParseConfigValue(raw json.RawMessage) (*RawConfigValue, error) {
	// Try plain string first
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return &RawConfigValue{value: str, needsUserToken: false}, nil
	}

	// Try reference object
	var ref map[string]string
	if err := json.Unmarshal(raw, &ref); err != nil {
		return nil, fmt.Errorf("config value must be string or reference object")
	}

	// Check for $env reference
	if envVar, ok := ref["$env"]; ok {
		value := os.Getenv(envVar)
		if value == "" {
			return nil, fmt.Errorf("environment variable %s not set", envVar)
		}
		// Strip surrounding quotes if present (only matching pairs)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		return &RawConfigValue{value: value, needsUserToken: false}, nil
	}

	// Check for $userToken reference
	if template, ok := ref["$userToken"]; ok {
		return &RawConfigValue{value: template, needsUserToken: true}, nil
	}

	return nil, fmt.Errorf("unknown reference type in config value")
}

// ParseConfigValueSlice parses a slice that may contain references
func ParseConfigValueSlice(raw []json.RawMessage) ([]string, []bool, error) {
	values := make([]string, len(raw))
	needsToken := make([]bool, len(raw))

	for i, item := range raw {
		parsed, err := ParseConfigValue(item)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing item %d: %w", i, err)
		}
		values[i] = parsed.value
		needsToken[i] = parsed.needsUserToken
	}

	return values, needsToken, nil
}

// ParseConfigValueMap parses a map that may contain references
func ParseConfigValueMap(raw map[string]json.RawMessage) (map[string]string, map[string]bool, error) {
	values := make(map[string]string)
	needsToken := make(map[string]bool)

	for key, item := range raw {
		parsed, err := ParseConfigValue(item)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing key %s: %w", key, err)
		}
		values[key] = parsed.value
		needsToken[key] = parsed.needsUserToken
	}

	return values, needsToken, nil
}
