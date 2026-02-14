package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	emailutil "github.com/dgellow/mcp-front/internal/emailutil"
	"golang.org/x/crypto/bcrypt"

	"github.com/dgellow/mcp-front/internal/log"
)

// UnmarshalJSON implements custom unmarshaling for MCPClientConfig
func (c *MCPClientConfig) UnmarshalJSON(data []byte) error {
	// Use a raw type to avoid recursion
	type rawConfig struct {
		TransportType      MCPClientType              `json:"transportType,omitempty"`
		Command            json.RawMessage            `json:"command,omitempty"`
		Args               []json.RawMessage          `json:"args,omitempty"`
		Env                map[string]json.RawMessage `json:"env,omitempty"`
		URL                json.RawMessage            `json:"url,omitempty"`
		Headers            map[string]json.RawMessage `json:"headers,omitempty"`
		Timeout            string                     `json:"timeout,omitempty"`
		Options            *Options                   `json:"options,omitempty"`
		RequiresUserToken  bool                       `json:"requiresUserToken,omitempty"`
		UserAuthentication *UserAuthentication        `json:"userAuthentication,omitempty"`
		ServiceAuths       []ServiceAuth              `json:"serviceAuths,omitempty"`
		InlineConfig       json.RawMessage            `json:"inline,omitempty"`
	}

	var raw rawConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	c.TransportType = raw.TransportType
	c.Options = raw.Options
	c.RequiresUserToken = raw.RequiresUserToken
	c.UserAuthentication = raw.UserAuthentication
	c.ServiceAuths = raw.ServiceAuths
	c.InlineConfig = raw.InlineConfig

	// Parse timeout if present
	if raw.Timeout != "" {
		timeout, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return fmt.Errorf("parsing timeout: %w", err)
		}
		c.Timeout = timeout
	}

	if c.TransportType == "" {
		return fmt.Errorf("transportType is required")
	}

	// Parse command if present
	if raw.Command != nil {
		parsed, err := ParseConfigValue(raw.Command)
		if err != nil {
			return fmt.Errorf("parsing command: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("command cannot be a user token reference")
		}
		c.Command = parsed.value
	}

	// Parse args if present
	if len(raw.Args) > 0 {
		values, needsToken, err := ParseConfigValueSlice(raw.Args)
		if err != nil {
			return fmt.Errorf("parsing args: %w", err)
		}
		c.Args = values
		c.ArgsNeedToken = needsToken
	}

	// Parse env if present
	if len(raw.Env) > 0 {
		values, needsToken, err := ParseConfigValueMap(raw.Env)
		if err != nil {
			return fmt.Errorf("parsing env: %w", err)
		}
		c.Env = values
		c.EnvNeedsToken = needsToken
	}

	// Parse URL if present
	if raw.URL != nil {
		parsed, err := ParseConfigValue(raw.URL)
		if err != nil {
			return fmt.Errorf("parsing url: %w", err)
		}
		c.URL = parsed.value
		c.URLNeedsToken = parsed.needsUserToken
	}

	// Parse headers if present
	if len(raw.Headers) > 0 {
		values, needsToken, err := ParseConfigValueMap(raw.Headers)
		if err != nil {
			return fmt.Errorf("parsing headers: %w", err)
		}
		c.Headers = values
		c.HeadersNeedToken = needsToken
	}

	return nil
}

// UnmarshalJSON implements custom unmarshaling for OAuthAuthConfig
func (o *OAuthAuthConfig) UnmarshalJSON(data []byte) error {
	// Use a raw type to parse references
	type rawOAuth struct {
		Kind                            AuthKind        `json:"kind"`
		Issuer                          json.RawMessage `json:"issuer"`
		GCPProject                      json.RawMessage `json:"gcpProject"`
		IDP                             json.RawMessage `json:"idp"`
		AllowedDomains                  []string        `json:"allowedDomains"`
		AllowedOrigins                  []string        `json:"allowedOrigins"`
		TokenTTL                        string          `json:"tokenTtl"`
		RefreshTokenTTL                 string          `json:"refreshTokenTtl"`
		RefreshTokenScopes              []string        `json:"refreshTokenScopes"`
		Storage                         string          `json:"storage"`
		FirestoreDatabase               string          `json:"firestoreDatabase,omitempty"`
		FirestoreCollection             string          `json:"firestoreCollection,omitempty"`
		JWTSecret                       json.RawMessage `json:"jwtSecret"`
		EncryptionKey                   json.RawMessage `json:"encryptionKey,omitempty"`
		DangerouslyAcceptIssuerAudience bool            `json:"dangerouslyAcceptIssuerAudience,omitempty"`
	}

	var raw rawOAuth
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Copy simple fields
	o.Kind = raw.Kind
	o.AllowedDomains = raw.AllowedDomains
	o.AllowedOrigins = raw.AllowedOrigins
	o.Storage = raw.Storage
	o.FirestoreDatabase = raw.FirestoreDatabase
	o.FirestoreCollection = raw.FirestoreCollection
	o.DangerouslyAcceptIssuerAudience = raw.DangerouslyAcceptIssuerAudience

	// RefreshTokenScopes: if set, refresh tokens are only issued when the
	// request includes at least one of these scopes. Empty slice means always
	// issue refresh tokens (recommended for MCP). Default: empty slice.
	if raw.RefreshTokenScopes != nil {
		o.RefreshTokenScopes = raw.RefreshTokenScopes
	} else {
		o.RefreshTokenScopes = []string{} // Default: always issue refresh tokens
	}

	// Parse TokenTTL duration (default: 1 hour)
	if raw.TokenTTL != "" {
		tokenTTL, err := time.ParseDuration(raw.TokenTTL)
		if err != nil {
			return fmt.Errorf("parsing tokenTtl: %w", err)
		}
		o.TokenTTL = tokenTTL
	} else {
		o.TokenTTL = time.Hour // Default: 1 hour
	}

	// Parse RefreshTokenTTL duration (default: 30 days)
	if raw.RefreshTokenTTL != "" {
		refreshTokenTTL, err := time.ParseDuration(raw.RefreshTokenTTL)
		if err != nil {
			return fmt.Errorf("parsing refreshTokenTtl: %w", err)
		}
		o.RefreshTokenTTL = refreshTokenTTL
	} else {
		o.RefreshTokenTTL = 30 * 24 * time.Hour // Default: 30 days
	}

	// Parse string fields
	if raw.Issuer != nil {
		parsed, err := ParseConfigValue(raw.Issuer)
		if err != nil {
			return fmt.Errorf("parsing issuer: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("issuer cannot be a user token reference")
		}
		o.Issuer = parsed.value
	}

	if raw.GCPProject != nil {
		parsed, err := ParseConfigValue(raw.GCPProject)
		if err != nil {
			return fmt.Errorf("parsing gcpProject: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("gcpProject cannot be a user token reference")
		}
		o.GCPProject = parsed.value
	}

	// Parse IDP config
	if raw.IDP != nil {
		idp, err := parseIDPConfig(raw.IDP)
		if err != nil {
			return fmt.Errorf("parsing idp: %w", err)
		}
		o.IDP = *idp
	}

	if raw.JWTSecret != nil {
		parsed, err := ParseConfigValue(raw.JWTSecret)
		if err != nil {
			return fmt.Errorf("parsing jwtSecret: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("jwtSecret cannot be a user token reference")
		}
		o.JWTSecret = Secret(parsed.value)
	}

	if raw.EncryptionKey != nil {
		parsed, err := ParseConfigValue(raw.EncryptionKey)
		if err != nil {
			return fmt.Errorf("parsing encryptionKey: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("encryptionKey cannot be a user token reference")
		}
		o.EncryptionKey = Secret(parsed.value)
	}

	// Validate JWT secret length
	if len(o.JWTSecret) < 32 {
		return fmt.Errorf("jwt secret must be at least 32 bytes, got %d", len(o.JWTSecret))
	}

	// Validate encryption key if storage requires it
	if o.Storage == "firestore" && o.EncryptionKey == "" {
		return fmt.Errorf("encryption key is required when using firestore storage")
	}
	if o.EncryptionKey != "" && len(o.EncryptionKey) != 32 {
		return fmt.Errorf("encryption key must be exactly 32 bytes, got %d", len(o.EncryptionKey))
	}

	return nil
}

// parseIDPConfig parses the IDP configuration with env var references
func parseIDPConfig(data json.RawMessage) (*IDPConfig, error) {
	type rawIDP struct {
		Provider         string          `json:"provider"`
		ClientID         json.RawMessage `json:"clientId"`
		ClientSecret     json.RawMessage `json:"clientSecret"`
		RedirectURI      json.RawMessage `json:"redirectUri"`
		DiscoveryURL     json.RawMessage `json:"discoveryUrl,omitempty"`
		AuthorizationURL json.RawMessage `json:"authorizationUrl,omitempty"`
		TokenURL         json.RawMessage `json:"tokenUrl,omitempty"`
		UserInfoURL      json.RawMessage `json:"userInfoUrl,omitempty"`
		Scopes           []string        `json:"scopes,omitempty"`
		TenantID         json.RawMessage `json:"tenantId,omitempty"`
		AllowedOrgs      []string        `json:"allowedOrgs,omitempty"`
	}

	var raw rawIDP
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	idp := &IDPConfig{
		Provider:    raw.Provider,
		Scopes:      raw.Scopes,
		AllowedOrgs: raw.AllowedOrgs,
	}

	// Helper to parse a field that cannot be a user token reference
	parseField := func(data json.RawMessage, fieldName string) (string, error) {
		if data == nil {
			return "", nil
		}
		parsed, err := ParseConfigValue(data)
		if err != nil {
			return "", fmt.Errorf("parsing %s: %w", fieldName, err)
		}
		if parsed.needsUserToken {
			return "", fmt.Errorf("%s cannot be a user token reference", fieldName)
		}
		return parsed.value, nil
	}

	var err error

	if idp.ClientID, err = parseField(raw.ClientID, "clientId"); err != nil {
		return nil, err
	}

	var clientSecret string
	if clientSecret, err = parseField(raw.ClientSecret, "clientSecret"); err != nil {
		return nil, err
	}
	idp.ClientSecret = Secret(clientSecret)

	if idp.RedirectURI, err = parseField(raw.RedirectURI, "redirectUri"); err != nil {
		return nil, err
	}

	if idp.DiscoveryURL, err = parseField(raw.DiscoveryURL, "discoveryUrl"); err != nil {
		return nil, err
	}

	if idp.AuthorizationURL, err = parseField(raw.AuthorizationURL, "authorizationUrl"); err != nil {
		return nil, err
	}

	if idp.TokenURL, err = parseField(raw.TokenURL, "tokenUrl"); err != nil {
		return nil, err
	}

	if idp.UserInfoURL, err = parseField(raw.UserInfoURL, "userInfoUrl"); err != nil {
		return nil, err
	}

	if idp.TenantID, err = parseField(raw.TenantID, "tenantId"); err != nil {
		return nil, err
	}

	return idp, nil
}

// UnmarshalJSON implements custom unmarshaling for ProxyConfig
func (p *ProxyConfig) UnmarshalJSON(data []byte) error {
	// Use a raw type to parse references
	type rawProxy struct {
		BaseURL  json.RawMessage `json:"baseURL"`
		Addr     json.RawMessage `json:"addr"`
		Name     string          `json:"name"`
		Auth     json.RawMessage `json:"auth"`
		Admin    *AdminConfig    `json:"admin"`
		Sessions *SessionConfig  `json:"sessions"`
	}

	var raw rawProxy
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	p.Name = raw.Name
	p.Admin = raw.Admin
	p.Sessions = raw.Sessions

	// Normalize admin emails for consistent comparison
	if p.Admin != nil && len(p.Admin.AdminEmails) > 0 {
		normalizedEmails := make([]string, len(p.Admin.AdminEmails))
		for i, emailAddr := range p.Admin.AdminEmails {
			normalizedEmails[i] = emailutil.Normalize(emailAddr)
		}
		p.Admin.AdminEmails = normalizedEmails
	}

	// Parse BaseURL
	if raw.BaseURL != nil {
		parsed, err := ParseConfigValue(raw.BaseURL)
		if err != nil {
			return fmt.Errorf("parsing baseURL: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("baseURL cannot be a user token reference")
		}
		p.BaseURL = parsed.value
	}

	// Parse Addr
	if raw.Addr != nil {
		parsed, err := ParseConfigValue(raw.Addr)
		if err != nil {
			return fmt.Errorf("parsing addr: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("addr cannot be a user token reference")
		}
		p.Addr = parsed.value
	}

	// Parse auth based on kind field
	if raw.Auth != nil {
		var authKind struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(raw.Auth, &authKind); err != nil {
			return fmt.Errorf("parsing auth kind: %w", err)
		}

		switch AuthKind(authKind.Kind) {
		case AuthKindOAuth:
			var oauth OAuthAuthConfig
			if err := json.Unmarshal(raw.Auth, &oauth); err != nil {
				return fmt.Errorf("parsing OAuth config: %w", err)
			}
			// Apply defaults for Firestore configuration
			if oauth.Storage == "firestore" {
				if oauth.FirestoreDatabase == "" {
					oauth.FirestoreDatabase = "(default)"
				}
				if oauth.FirestoreCollection == "" {
					oauth.FirestoreCollection = "mcp_front_data"
				}
			}
			p.Auth = &oauth
		default:
			return fmt.Errorf("unknown auth kind: %s (only 'oauth' is supported for proxy auth)", authKind.Kind)
		}
	}

	return nil
}

// ApplyUserToken creates a copy of the config with user tokens substituted
func (c *MCPClientConfig) ApplyUserToken(userToken string) *MCPClientConfig {
	if userToken == "" || !c.RequiresUserToken {
		return c
	}

	result := *c

	// Copy and apply token to env vars
	if c.Env != nil {
		result.Env = make(map[string]string, len(c.Env))
		for key, value := range c.Env {
			if c.EnvNeedsToken != nil && c.EnvNeedsToken[key] {
				result.Env[key] = strings.ReplaceAll(value, "{{token}}", userToken)
			} else {
				result.Env[key] = value
			}
		}
	}

	// Copy and apply token to args
	if c.Args != nil {
		result.Args = make([]string, len(c.Args))
		for i, arg := range c.Args {
			if c.ArgsNeedToken != nil && i < len(c.ArgsNeedToken) && c.ArgsNeedToken[i] {
				result.Args[i] = strings.ReplaceAll(arg, "{{token}}", userToken)
			} else {
				result.Args[i] = arg
			}
		}
	}

	// Apply token to URL if needed
	if c.URLNeedsToken {
		result.URL = strings.ReplaceAll(c.URL, "{{token}}", userToken)
	}

	// Copy and apply token to headers
	if c.Headers != nil {
		result.Headers = make(map[string]string, len(c.Headers))
		for key, value := range c.Headers {
			if c.HeadersNeedToken != nil && c.HeadersNeedToken[key] {
				result.Headers[key] = strings.ReplaceAll(value, "{{token}}", userToken)
			} else {
				result.Headers[key] = value
			}
		}
	}

	// Clear tracking maps (no longer needed after token substitution)
	result.EnvNeedsToken = nil
	result.ArgsNeedToken = nil
	result.URLNeedsToken = false
	result.HeadersNeedToken = nil

	return &result
}

// UnmarshalJSON implements custom unmarshaling for ServiceAuth
func (s *ServiceAuth) UnmarshalJSON(data []byte) error {
	// Use type alias to avoid recursion
	type rawServiceAuth ServiceAuth
	var raw rawServiceAuth

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Copy all fields
	*s = ServiceAuth(raw)

	log.LogTraceWithFields("config", "Unmarshaling service auth", map[string]any{
		"type": s.Type,
	})

	// Parse password if provided (for basic auth)
	if s.PasswordRaw != nil {
		log.LogTraceWithFields("config", "Parsing password for basic auth", map[string]any{
			"username": s.Username,
		})
		parsed, err := ParseConfigValue(s.PasswordRaw)
		if err != nil {
			return fmt.Errorf("parsing password: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("password cannot be a user token reference")
		}

		// Hash the password using bcrypt
		log.LogTraceWithFields("config", "Hashing password for basic auth", map[string]any{
			"username": s.Username,
		})
		hashed, err := bcrypt.GenerateFromPassword([]byte(parsed.value), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hashing password: %w", err)
		}
		s.HashedPassword = Secret(hashed)
	}

	// Parse user token if provided
	if s.UserTokenRaw != nil {
		log.LogTraceWithFields("config", "Parsing user token for service auth", map[string]any{
			"type": s.Type,
		})
		parsed, err := ParseConfigValue(s.UserTokenRaw)
		if err != nil {
			return fmt.Errorf("parsing userToken: %w", err)
		}
		if parsed.needsUserToken {
			return fmt.Errorf("userToken cannot be a user token reference")
		}
		s.UserToken = Secret(parsed.value)
	}

	// Validate required fields based on type
	switch s.Type {
	case ServiceAuthTypeBasic:
		if s.Username == "" {
			return fmt.Errorf("username is required for basic auth")
		}
		if s.PasswordRaw == nil {
			return fmt.Errorf("password is required for basic auth")
		}
	case ServiceAuthTypeBearer:
		if len(s.Tokens) == 0 {
			return fmt.Errorf("at least one token is required for bearer auth")
		}
	default:
		return fmt.Errorf("unknown service auth type: %s", s.Type)
	}

	return nil
}

// UnmarshalJSON implements custom unmarshaling for UserAuthentication
func (u *UserAuthentication) UnmarshalJSON(data []byte) error {
	// First unmarshal to get the type
	// Use type alias to avoid recursion
	type rawAuth UserAuthentication
	var raw rawAuth

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Copy all fields
	*u = UserAuthentication(raw)

	// Set default token format if not specified
	if u.TokenFormat == "" {
		u.TokenFormat = "{{token}}"
	}

	switch u.Type {
	case UserAuthTypeOAuth:
		// Parse OAuth credentials
		if u.ClientIDRaw != nil {
			parsed, err := ParseConfigValue(u.ClientIDRaw)
			if err != nil {
				return fmt.Errorf("parsing clientId: %w", err)
			}
			u.ClientID = Secret(parsed.value)
		}

		if u.ClientSecretRaw != nil {
			parsed, err := ParseConfigValue(u.ClientSecretRaw)
			if err != nil {
				return fmt.Errorf("parsing clientSecret: %w", err)
			}
			u.ClientSecret = Secret(parsed.value)
		}

	case UserAuthTypeManual:
		// Compile validation regex if present
		if u.Validation != "" {
			regex, err := regexp.Compile(u.Validation)
			if err != nil {
				return fmt.Errorf("compiling validation regex: %w", err)
			}
			u.ValidationRegex = regex
		}

	default:
		return fmt.Errorf("unknown user auth type: %s", u.Type)
	}

	return nil
}

// UnmarshalJSON implements custom unmarshaling for SessionConfig
func (s *SessionConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Timeout         string `json:"timeout"`
		CleanupInterval string `json:"cleanupInterval"`
		MaxPerUser      *int   `json:"maxPerUser"` // Pointer to detect explicit 0
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Parse timeout if present
	if raw.Timeout != "" {
		timeout, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return fmt.Errorf("parsing timeout: %w", err)
		}
		s.Timeout = timeout
	}

	// Parse cleanupInterval if present
	if raw.CleanupInterval != "" {
		interval, err := time.ParseDuration(raw.CleanupInterval)
		if err != nil {
			return fmt.Errorf("parsing cleanupInterval: %w", err)
		}
		s.CleanupInterval = interval
	}

	// Set MaxPerUser if present (0 is a valid value, means no upper bound)
	if raw.MaxPerUser != nil {
		s.MaxPerUser = *raw.MaxPerUser
	}

	return nil
}
