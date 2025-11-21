# OAuth User Authentication for MCP Servers

## Overview

Add OAuth authentication support for MCP servers with an interstitial service selection page, allowing users to connect multiple OAuth-based services after Google authentication before returning to Claude.ai.

## User Flow

```
1. Claude.ai → User clicks "Connect" on MCP integration
2. → Redirected to mcp-front Google OAuth
3. → User completes Google OAuth
4. → mcp-front shows interstitial page listing OAuth-requiring services
5. → User optionally connects to services (e.g., Stainless, Linear)
6. → Each service OAuth completes and returns to interstitial
7. → User clicks "Continue to Claude" 
8. → mcp-front redirects back to Claude.ai with original auth code
9. → Complete! User connected to mcp-front and optionally to services
```

## Config Structure

### OAuth Authentication

```json
{
  "mcpServers": {
    "stainless": {
      "transportType": "stdio",
      "command": "stainless",
      "args": ["mcp"],
      "env": {
        "STAINLESS_API_TOKEN": {"$userToken": "{{token}}"}
      },
      "requiresUserToken": true,
      "userAuthentication": {
        "type": "oauth",
        "displayName": "Stainless",
        "clientId": {"$env": "STAINLESS_OAUTH_CLIENT_ID"},
        "clientSecret": {"$env": "STAINLESS_OAUTH_CLIENT_SECRET"},
        "authorizationUrl": "https://api.stainless.com/oauth/authorize",
        "tokenUrl": "https://api.stainless.com/oauth/token",
        "scopes": ["mcp:read", "mcp:write"],
        "tokenFormat": "Bearer {{token}}"
      }
    }
  }
}
```

### Manual Token Authentication

```json
{
  "mcpServers": {
    "notion": {
      "transportType": "stdio",
      "command": "notion-mcp",
      "args": [],
      "env": {
        "NOTION_API_KEY": {"$userToken": "{{token}}"}
      },
      "requiresUserToken": true,
      "userAuthentication": {
        "type": "manual",
        "displayName": "Notion API Token",
        "instructions": "Get your token from https://notion.so/my-integrations",
        "helpUrl": "https://developers.notion.com/docs/authorization",
        "tokenFormat": "{{token}}",
        "validation": "^secret_[a-zA-Z0-9]{43}$"
      }
    }
  }
}
```

## Implementation Details

### 1. Interstitial Service Selection Page

After Google OAuth completes, show a page allowing users to connect OAuth-requiring services:

```go
// In GoogleCallbackHandler:
func (h *AuthHandlers) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
    // ... complete Google OAuth ...
    
    // For OAuth client flow, check if any services need OAuth
    if needsServiceAuth := h.checkServicesNeedOAuth(userEmail); needsServiceAuth {
        // Encrypt Claude's OAuth state for later
        encryptedState := h.encryptOAuthState(OAuthState{
            AuthCode:     authCode,
            State:        originalState,
            RedirectURI:  originalRedirectURI,
            Timestamp:    time.Now(),
        })
        
        // Redirect to service selection page
        http.Redirect(w, r, fmt.Sprintf("/oauth/services?state=%s", encryptedState), http.StatusFound)
        return
    }
    
    // No services need OAuth, complete Claude flow
    h.completeClaudeOAuth(w, r, authCode, originalState, originalRedirectURI)
}

// Service selection page shows:
// - List of OAuth-requiring services from config
// - Current connection status for each
// - Connect/Reconnect buttons
// - "Continue to Claude" button
```

### 2. Service OAuth Endpoints

```go
// GET /oauth/connect?service={serviceName}&return={encodedReturnURL}
func (h *ServiceAuthHandlers) ConnectHandler(w http.ResponseWriter, r *http.Request) {
    serviceName := r.URL.Query().Get("service")
    returnURL := r.URL.Query().Get("return")
    
    // Validate service supports OAuth
    serviceConfig := h.mcpServers[serviceName]
    if !serviceConfig.RequiresUserToken || 
       serviceConfig.UserAuthentication.Type != UserAuthTypeOAuth {
        // Redirect back with error
        return
    }
    
    // Start OAuth flow with service
    authURL, err := h.oauthClient.StartOAuthFlow(
        ctx, userEmail, serviceName, serviceConfig, returnURL)
    
    http.Redirect(w, r, authURL, http.StatusFound)
}

// GET /oauth/callback/{serviceName}
func (h *ServiceAuthHandlers) CallbackHandler(w http.ResponseWriter, r *http.Request) {
    serviceName := getServiceFromPath(r.URL.Path)
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    
    if errorParam := r.URL.Query().Get("error"); errorParam != "" {
        // Service OAuth failed - redirect to interstitial with error
        returnURL := h.getReturnURLFromState(state)
        errorURL := fmt.Sprintf("%s&error=%s&service=%s", 
            returnURL, errorParam, serviceName)
        http.Redirect(w, r, errorURL, http.StatusFound)
        return
    }
    
    // Exchange code for tokens
    tokens, returnURL, err := h.oauthClient.HandleCallback(
        ctx, serviceName, code, state, serviceConfig)
    
    // Store encrypted tokens
    h.storage.SetUserToken(ctx, userEmail, serviceName, &StoredToken{
        Type:      TokenTypeOAuth,
        OAuthData: tokens,
        UpdatedAt: time.Now(),
    })
    
    // Redirect back to interstitial page
    http.Redirect(w, r, returnURL, http.StatusFound)
}
```

### 3. Enhanced Config Types

```go
type UserAuthType string

const (
    UserAuthTypeManual UserAuthType = "manual"
    UserAuthTypeOAuth  UserAuthType = "oauth"
)

type UserAuthentication struct {
    Type        UserAuthType `json:"type"`
    DisplayName string       `json:"displayName"`
    
    // For OAuth
    ClientID         json.RawMessage `json:"clientId,omitempty"`
    ClientSecret     json.RawMessage `json:"clientSecret,omitempty"`
    AuthorizationURL string          `json:"authorizationUrl,omitempty"`
    TokenURL         string          `json:"tokenUrl,omitempty"`
    Scopes           []string        `json:"scopes,omitempty"`
    
    // For Manual  
    Instructions string `json:"instructions,omitempty"`
    HelpURL      string `json:"helpUrl,omitempty"`
    Validation   string `json:"validation,omitempty"`
    
    // Common
    TokenFormat string `json:"tokenFormat,omitempty"`
    
    // Resolved values (not in JSON)
    ResolvedClientID     string `json:"-"`
    ResolvedClientSecret string `json:"-"`
    CompiledValidation   *regexp.Regexp `json:"-"`
}
```

### 4. Token Storage with OAuth Metadata

```go
type OAuthTokenData struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`
    ExpiresAt    time.Time `json:"expires_at"`
    Scopes       []string  `json:"scopes"`
}

type StoredUserToken struct {
    Type      UserAuthType    `json:"type"`
    Token     string          `json:"token,omitempty"`     // For manual
    OAuthData *OAuthTokenData `json:"oauth,omitempty"`     // For OAuth
    UpdatedAt time.Time       `json:"updated_at"`
}
```

### 5. Automatic Token Refresh

```go
func (h *MCPHandler) getUserTokenIfAvailable(ctx context.Context, userEmail string) (string, error) {
    stored, err := h.storage.GetUserToken(ctx, userEmail, h.serverName)
    if err != nil {
        return "", err
    }
    
    if stored.Type == UserAuthTypeOAuth && stored.OAuthData != nil {
        // Check if token needs refresh
        if time.Now().After(stored.OAuthData.ExpiresAt.Add(-5 * time.Minute)) {
            // Refresh token
            client := NewOAuthClient(h.serverConfig.UserAuthentication)
            newTokens, err := client.RefreshToken(ctx, stored.OAuthData.RefreshToken)
            if err != nil {
                return "", fmt.Errorf("token refresh failed: %w", err)
            }
            
            // Update storage
            stored.OAuthData = newTokens
            stored.UpdatedAt = time.Now()
            h.storage.SetUserToken(ctx, userEmail, h.serverName, stored)
        }
        
        // Format token
        return formatToken(h.serverConfig.UserAuthentication.TokenFormat, 
                         stored.OAuthData.AccessToken), nil
    }
    
    // Manual token
    return formatToken(h.serverConfig.UserAuthentication.TokenFormat, stored.Token), nil
}
```

### 6. State Management

```go
// Encrypted state for preserving Claude OAuth while doing service auth
type OAuthState struct {
    AuthCode     string    `json:"code"`
    State        string    `json:"state"`
    RedirectURI  string    `json:"redirect_uri"`
    Timestamp    time.Time `json:"timestamp"`
}

func (h *AuthHandlers) encryptOAuthState(state OAuthState) string {
    data, _ := json.Marshal(state)
    encrypted, _ := h.encryptor.Encrypt(string(data))
    // Add HMAC for tamper protection
    signature := crypto.SignData(encrypted, h.encryptionKey)
    return base64.URLEncoding.EncodeToString(
        []byte(fmt.Sprintf("%s.%s", encrypted, signature)))
}

func (h *AuthHandlers) decryptOAuthState(encrypted string) (*OAuthState, error) {
    // Verify HMAC signature
    // Check timestamp (10 minute expiry)
    // Decrypt and unmarshal
}
```

### 7. Interstitial Page UI

```go
// GET /oauth/services?state={encryptedState}
func (h *AuthHandlers) ServiceSelectionHandler(w http.ResponseWriter, r *http.Request) {
    encryptedState := r.URL.Query().Get("state")
    
    // Get OAuth-requiring services and their status
    services := []ServiceStatus{}
    for name, config := range h.mcpServers {
        if config.RequiresUserToken && 
           config.UserAuthentication.Type == UserAuthTypeOAuth {
            
            // Check if user already has valid token
            token, _ := h.storage.GetUserToken(ctx, userEmail, name)
            status := "not_connected"
            if token != nil && !token.IsExpired() {
                status = "connected"
            }
            
            services = append(services, ServiceStatus{
                Name:        name,
                DisplayName: config.UserAuthentication.DisplayName,
                Status:      status,
                Error:       r.URL.Query().Get("error") == name,
            })
        }
    }
    
    // Render template showing:
    // - Service list with Connect/Connected/Failed states
    // - "Skip for now" and "Continue to Claude" buttons
    // - Clear messaging that this is optional
}
```

### 8. Routes Configuration

```go
// OAuth endpoints
mux.Handle("/authorize", authHandlers.AuthorizeHandler)
mux.Handle("/oauth/callback", authHandlers.GoogleCallbackHandler)
mux.Handle("/token", authHandlers.TokenHandler)

// Service OAuth endpoints  
mux.Handle("/oauth/services", authHandlers.ServiceSelectionHandler)
mux.Handle("/oauth/connect", serviceAuthHandlers.ConnectHandler)
mux.Handle("/oauth/callback/", serviceAuthHandlers.CallbackHandler)
mux.Handle("/oauth/complete", authHandlers.CompleteClaudeOAuthHandler)

// Token management UI
mux.Handle("/my/tokens", tokenHandlers.ListTokensHandler)
```

## Benefits

1. **Clear User Intent**: Users explicitly choose which services to connect
2. **No Protocol Violations**: Standard OAuth flow without custom parameters
3. **Progressive Disclosure**: Only OAuth-requiring services shown
4. **Flexible**: Connect some services now, others later
5. **Error Recovery**: Service OAuth failures don't block Claude connection
6. **Automatic Refresh**: OAuth tokens refreshed transparently

## Security Considerations

1. **State parameter**: HMAC-signed to prevent tampering
2. **OAuth secrets**: Encrypted at rest in storage
3. **Token refresh**: Automatic refresh 5 minutes before expiry
4. **Isolation**: Each service has separate OAuth configuration
5. **Time limits**: Encrypted state expires after 10 minutes
6. **Error handling**: Service OAuth failures don't compromise main flow

## Example: Complete Flow

1. User in Claude.ai clicks "Connect MCP"
2. Claude.ai redirects to: `https://mcp-front.com/authorize?client_id=claude&redirect_uri=https://claude.ai/callback&state=abc123`
3. User completes Google OAuth  
4. mcp-front shows interstitial page:
   ```
   Some MCP servers require additional authentication:
   
   Stainless [Connect]
   Linear    [Connected ✓]
   
   [Skip for now] [Continue to Claude]
   ```
5. User clicks "Connect" for Stainless
6. Redirected to: `https://api.stainless.com/oauth/authorize?...`
7. User approves Stainless access
8. Returns to interstitial showing: Stainless [Connected ✓]
9. User clicks "Continue to Claude"
10. mcp-front redirects to: `https://claude.ai/callback?code=...&state=abc123`
11. Complete! User connected to both mcp-front and Stainless

