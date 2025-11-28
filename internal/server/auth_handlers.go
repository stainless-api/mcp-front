package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/browserauth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/envutil"
	"github.com/dgellow/mcp-front/internal/googleauth"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/oauthsession"
	"github.com/dgellow/mcp-front/internal/storage"
	"github.com/ory/fosite"
)

// AuthHandlers provides OAuth HTTP handlers with dependency injection
type AuthHandlers struct {
	oauthProvider      fosite.OAuth2Provider
	authConfig         config.OAuthAuthConfig
	storage            storage.Storage
	sessionEncryptor   crypto.Encryptor
	mcpServers         map[string]*config.MCPClientConfig
	oauthStateToken    crypto.TokenSigner
	serviceOAuthClient *auth.ServiceOAuthClient
}

// UpstreamOAuthState stores OAuth state during upstream authentication flow (MCP host → mcp-front)
type UpstreamOAuthState struct {
	UserInfo     googleauth.UserInfo `json:"user_info"`
	ClientID     string              `json:"client_id"`
	RedirectURI  string              `json:"redirect_uri"`
	Scopes       []string            `json:"scopes"`
	State        string              `json:"state"`
	ResponseType string              `json:"response_type"`
}

// NewAuthHandlers creates new auth handlers with dependency injection
func NewAuthHandlers(
	oauthProvider fosite.OAuth2Provider,
	authConfig config.OAuthAuthConfig,
	storage storage.Storage,
	sessionEncryptor crypto.Encryptor,
	mcpServers map[string]*config.MCPClientConfig,
	serviceOAuthClient *auth.ServiceOAuthClient,
) *AuthHandlers {
	return &AuthHandlers{
		oauthProvider:      oauthProvider,
		authConfig:         authConfig,
		storage:            storage,
		sessionEncryptor:   sessionEncryptor,
		mcpServers:         mcpServers,
		oauthStateToken:    crypto.NewTokenSigner([]byte(authConfig.EncryptionKey), 10*time.Minute),
		serviceOAuthClient: serviceOAuthClient,
	}
}

// WellKnownHandler serves OAuth 2.0 Authorization Server Metadata (RFC 8414)
func (h *AuthHandlers) WellKnownHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Well-known handler called: %s %s", r.Method, r.URL.Path)

	metadata, err := oauth.AuthorizationServerMetadata(h.authConfig.Issuer)
	if err != nil {
		log.LogError("Failed to build authorization server metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.LogError("Failed to encode well-known metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
	}
}

// ProtectedResourceMetadataHandler serves OAuth 2.0 Protected Resource Metadata (RFC 9728)
// This endpoint helps clients discover which authorization servers this resource server trusts
func (h *AuthHandlers) ProtectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Protected resource metadata handler called: %s %s", r.Method, r.URL.Path)

	metadata, err := oauth.ProtectedResourceMetadata(h.authConfig.Issuer)
	if err != nil {
		log.LogError("Failed to build protected resource metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.LogError("Failed to encode protected resource metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
	}
}

func (h *AuthHandlers) ClientMetadataHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	if clientID == "" {
		jsonwriter.WriteBadRequest(w, "Missing client_id")
		return
	}

	log.Logf("Client metadata handler called for client: %s", clientID)

	client, err := h.storage.GetClientWithMetadata(r.Context(), clientID)
	if err != nil {
		log.LogError("Failed to get client %s: %v", clientID, err)
		if errors.Is(err, fosite.ErrNotFound) {
			jsonwriter.WriteNotFound(w, "Client not found")
		} else {
			jsonwriter.WriteInternalServerError(w, "Failed to retrieve client")
		}
		return
	}

	tokenEndpointAuthMethod := "none"
	if len(client.Secret) > 0 {
		tokenEndpointAuthMethod = "client_secret_post"
	}

	metadata := oauth.BuildClientMetadata(
		client.ID,
		client.RedirectURIs,
		client.GrantTypes,
		client.ResponseTypes,
		client.Scopes,
		tokenEndpointAuthMethod,
		client.CreatedAt,
	)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.LogError("Failed to encode client metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
	}
}

// AuthorizeHandler handles OAuth 2.0 authorization requests
func (h *AuthHandlers) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log.Logf("Authorize handler called: %s %s", r.Method, r.URL.Path)

	// In development mode, generate a secure state parameter if missing
	// This works around bugs in OAuth clients that don't send state
	stateParam := r.URL.Query().Get("state")
	if envutil.IsDev() && len(stateParam) == 0 {
		generatedState := crypto.GenerateSecureToken()
		log.LogWarn("Development mode: generating state parameter '%s' for buggy client", generatedState)
		q := r.URL.Query()
		q.Set("state", generatedState)
		r.URL.RawQuery = q.Encode()
		// Also update the form values
		if r.Form == nil {
			_ = r.ParseForm()
		}
		r.Form.Set("state", generatedState)
	}

	// Parse the authorize request
	ar, err := h.oauthProvider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.LogError("Authorize request error: %v", err)
		h.oauthProvider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Extract and validate resource parameters (RFC 8707)
	resources, err := oauth.ExtractResourceParameters(r)
	if err != nil {
		log.LogError("Failed to extract resource parameters: %v", err)
		h.oauthProvider.WriteAuthorizeError(ctx, w, ar, fosite.ErrInvalidRequest.WithHint("Invalid resource parameter"))
		return
	}

	// Validate each resource URI per RFC 8707
	for _, resource := range resources {
		if err := oauth.ValidateResourceURI(resource, h.authConfig.Issuer); err != nil {
			log.LogErrorWithFields("auth", "Invalid resource URI in authorization request", map[string]any{
				"resource": resource,
				"error":    err.Error(),
			})
			h.oauthProvider.WriteAuthorizeError(ctx, w, ar, fosite.ErrInvalidRequest.WithHintf("Invalid resource: %v", err))
			return
		}
	}

	// Grant audiences for requested resources (RFC 8707)
	// These audience claims will be included in issued tokens
	for _, resource := range resources {
		ar.GrantAudience(resource)
		log.LogInfoWithFields("auth", "Granted audience for resource", map[string]any{
			"resource": resource,
			"client":   ar.GetClient().GetID(),
		})
	}

	state := ar.GetState()
	h.storage.StoreAuthorizeRequest(state, ar)

	authURL := googleauth.GoogleAuthURL(h.authConfig, state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GoogleCallbackHandler handles the callback from Google OAuth
func (h *AuthHandlers) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.LogError("Google OAuth error: %s - %s", errMsg, errDesc)
		jsonwriter.WriteBadRequest(w, fmt.Sprintf("Authentication failed: %s", errMsg))
		return
	}

	if state == "" || code == "" {
		log.LogError("Missing state or code in callback")
		jsonwriter.WriteBadRequest(w, "Invalid callback parameters")
		return
	}

	var ar fosite.AuthorizeRequester
	var isBrowserFlow bool
	var returnURL string

	if strings.HasPrefix(state, "browser:") {
		isBrowserFlow = true
		stateToken := strings.TrimPrefix(state, "browser:")

		var browserState browserauth.AuthorizationState
		if err := h.oauthStateToken.Verify(stateToken, &browserState); err != nil {
			log.LogError("Invalid browser state: %v", err)
			jsonwriter.WriteBadRequest(w, "Invalid state parameter")
			return
		}
		returnURL = browserState.ReturnURL
	} else {
		// OAuth client flow - retrieve stored authorize request
		var found bool
		ar, found = h.storage.GetAuthorizeRequest(state)
		if !found {
			log.LogError("Invalid or expired state: %s", state)
			jsonwriter.WriteBadRequest(w, "Invalid or expired authorization request")
			return
		}
	}

	// Exchange code for token with timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	token, err := googleauth.ExchangeCodeForToken(ctx, h.authConfig, code)
	if err != nil {
		log.LogError("Failed to exchange code: %v", err)
		if !isBrowserFlow && ar != nil {
			h.oauthProvider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithHint("Failed to exchange authorization code"))
		} else {
			jsonwriter.WriteInternalServerError(w, "Authentication failed")
		}
		return
	}

	// Validate user
	userInfo, err := googleauth.ValidateUser(ctx, h.authConfig, token)
	if err != nil {
		log.LogError("User validation failed: %v", err)
		if !isBrowserFlow && ar != nil {
			h.oauthProvider.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied.WithHint(err.Error()))
		} else {
			jsonwriter.WriteForbidden(w, "Access denied")
		}
		return
	}

	log.Logf("User authenticated: %s", userInfo.Email)

	// Store user in database
	if err := h.storage.UpsertUser(ctx, userInfo.Email); err != nil {
		log.LogWarnWithFields("auth", "Failed to track user", map[string]any{
			"email": userInfo.Email,
			"error": err.Error(),
		})
	}

	if isBrowserFlow {
		// Browser SSO flow - set encrypted session cookie
		// Browser sessions should last longer than API tokens for better UX
		sessionDuration := 24 * time.Hour

		sessionData := browserauth.SessionCookie{
			Email:   userInfo.Email,
			Expires: time.Now().Add(sessionDuration),
		}

		// Marshal session data to JSON
		jsonData, err := json.Marshal(sessionData)
		if err != nil {
			log.LogError("Failed to marshal session data: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create session")
			return
		}

		// Encrypt session data
		encryptedData, err := h.sessionEncryptor.Encrypt(string(jsonData))
		if err != nil {
			log.LogError("Failed to encrypt session: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create session")
			return
		}

		// Set secure session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "mcp_session",
			Value:    encryptedData,
			Path:     "/",
			HttpOnly: true,
			Secure:   !envutil.IsDev(),
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(sessionDuration.Seconds()),
		})

		log.LogInfoWithFields("auth", "Browser SSO session created", map[string]any{
			"user":      userInfo.Email,
			"duration":  sessionDuration,
			"returnURL": returnURL,
		})

		// Redirect to return URL
		http.Redirect(w, r, returnURL, http.StatusFound)
		return
	}

	// OAuth client flow - check if any services need OAuth
	needsServiceAuth := false
	for _, serverConfig := range h.mcpServers {
		if serverConfig.RequiresUserToken &&
			serverConfig.UserAuthentication != nil &&
			serverConfig.UserAuthentication.Type == config.UserAuthTypeOAuth {
			needsServiceAuth = true
			break
		}
	}

	if needsServiceAuth {
		stateData, err := h.signUpstreamOAuthState(ar, userInfo)
		if err != nil {
			log.LogError("Failed to sign OAuth state: %v", err)
			h.oauthProvider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithHint("Failed to prepare service authentication"))
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/oauth/services?state=%s", url.QueryEscape(stateData)), http.StatusFound)
		return
	}

	// Create session for token issuance
	// Note: Audience claims are stored in the authorize request (ar.GetGrantedAudience())
	// and will be automatically propagated to access tokens by fosite
	session := &oauthsession.Session{
		DefaultSession: &fosite.DefaultSession{
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().Add(h.authConfig.TokenTTL),
				fosite.RefreshToken: time.Now().Add(h.authConfig.TokenTTL * 2),
			},
		},
		UserInfo: userInfo,
	}

	// Accept the authorization request
	response, err := h.oauthProvider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.LogError("Authorize response error: %v", err)
		h.oauthProvider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	h.oauthProvider.WriteAuthorizeResponse(ctx, w, ar, response)
}

// TokenHandler handles OAuth 2.0 token requests
func (h *AuthHandlers) TokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Token handler called: %s %s", r.Method, r.URL.Path)
	ctx := r.Context()

	// Create session for the token exchange
	// Note: We create our custom Session type here, and fosite will populate it
	// with the session data from the authorization code during NewAccessRequest
	session := &oauthsession.Session{DefaultSession: &fosite.DefaultSession{}}

	// Handle token request - this retrieves the session from the authorization code
	accessRequest, err := h.oauthProvider.NewAccessRequest(ctx, r, session)
	if err != nil {
		log.LogError("Access request error: %v", err)
		h.oauthProvider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// At this point, accessRequest.GetSession() contains the session data from
	// the authorization phase (including our custom UserInfo). Fosite handles
	// the session propagation internally when creating the access token.

	// Generate tokens
	response, err := h.oauthProvider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.LogError("Access response error: %v", err)
		h.oauthProvider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	h.oauthProvider.WriteAccessResponse(ctx, w, accessRequest, response)
}

func (h *AuthHandlers) buildClientRegistrationResponse(client *storage.Client, tokenEndpointAuthMethod string, clientSecret string) map[string]any {
	response := map[string]any{
		"client_id":                  client.ID,
		"client_id_issued_at":        client.CreatedAt,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"scope":                      strings.Join(client.Scopes, " "),
		"token_endpoint_auth_method": tokenEndpointAuthMethod,
	}

	if clientSecret != "" {
		response["client_secret"] = clientSecret
	}

	return response
}

// RegisterHandler handles dynamic client registration (RFC 7591)
func (h *AuthHandlers) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Register handler called: %s %s", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	// Parse client metadata
	var metadata map[string]any
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		jsonwriter.WriteBadRequest(w, "Invalid request body")
		return
	}

	// Parse client request
	redirectURIs, scopes, err := googleauth.ParseClientRequest(metadata)
	if err != nil {
		log.LogError("Client request parsing error: %v", err)
		jsonwriter.WriteBadRequest(w, err.Error())
		return
	}

	tokenEndpointAuthMethod := "none"
	var client *storage.Client
	var plaintextSecret string
	clientID := crypto.GenerateSecureToken()

	if authMethod, ok := metadata["token_endpoint_auth_method"].(string); ok && authMethod == "client_secret_post" {
		plaintextSecret = crypto.GenerateSecureToken()
		hashedSecret, err := crypto.HashClientSecret(plaintextSecret)
		if err != nil {
			log.LogError("Failed to hash client secret: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create client")
			return
		}
		client, err = h.storage.CreateConfidentialClient(r.Context(), clientID, hashedSecret, redirectURIs, scopes, h.authConfig.Issuer)
		if err != nil {
			log.LogError("Failed to create confidential client: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create client")
			return
		}
		tokenEndpointAuthMethod = "client_secret_post"
		log.Logf("Creating confidential client %s with client_secret_post authentication", clientID)
	} else {
		client, err = h.storage.CreateClient(r.Context(), clientID, redirectURIs, scopes, h.authConfig.Issuer)
		if err != nil {
			log.LogError("Failed to create client: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create client")
			return
		}
		log.Logf("Creating public client %s with no authentication", clientID)
	}

	response := h.buildClientRegistrationResponse(client, tokenEndpointAuthMethod, plaintextSecret)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.LogError("Failed to encode registration response: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to create client")
	}
}

// signUpstreamOAuthState signs upstream OAuth state for secure storage
func (h *AuthHandlers) signUpstreamOAuthState(ar fosite.AuthorizeRequester, userInfo googleauth.UserInfo) (string, error) {
	state := UpstreamOAuthState{
		UserInfo:     userInfo,
		ClientID:     ar.GetClient().GetID(),
		RedirectURI:  ar.GetRedirectURI().String(),
		Scopes:       ar.GetRequestedScopes(),
		State:        ar.GetState(),
		ResponseType: ar.GetResponseTypes()[0],
	}

	return h.oauthStateToken.Sign(state)
}

// verifyUpstreamOAuthState verifies and validates upstream OAuth state
func (h *AuthHandlers) verifyUpstreamOAuthState(signedState string) (*UpstreamOAuthState, error) {
	var state UpstreamOAuthState
	if err := h.oauthStateToken.Verify(signedState, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// ServiceSelectionHandler shows the interstitial page for selecting services to connect
func (h *AuthHandlers) ServiceSelectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	signedState := r.URL.Query().Get("state")
	if signedState == "" {
		jsonwriter.WriteBadRequest(w, "Missing state parameter")
		return
	}

	upstreamOAuthState, err := h.verifyUpstreamOAuthState(signedState)
	if err != nil {
		log.LogError("Failed to verify OAuth state: %v", err)
		jsonwriter.WriteBadRequest(w, "Invalid or expired session")
		return
	}

	userEmail := upstreamOAuthState.UserInfo.Email

	// Prepare template data
	returnURL := fmt.Sprintf("/oauth/services?state=%s", url.QueryEscape(signedState))

	// Prepare service list
	var services []ServiceSelectionData
	for name, serverConfig := range h.mcpServers {
		if serverConfig.RequiresUserToken &&
			serverConfig.UserAuthentication != nil &&
			serverConfig.UserAuthentication.Type == config.UserAuthTypeOAuth {

			// Check if user already has valid token
			token, _ := h.storage.GetUserToken(r.Context(), userEmail, name)
			status := "not_connected"
			if token != nil {
				status = "connected"
			}

			displayName := name
			if serverConfig.UserAuthentication.DisplayName != "" {
				displayName = serverConfig.UserAuthentication.DisplayName
			}

			// Check for error from callback
			errorMsg := ""
			if r.URL.Query().Get("error") != "" && r.URL.Query().Get("service") == name {
				status = "error"
				// Use error_msg if available, fallback to error_description
				errorMsg = r.URL.Query().Get("error_msg")
				if errorMsg == "" {
					errorMsg = r.URL.Query().Get("error_description")
				}
				if errorMsg == "" {
					errorMsg = "OAuth connection failed"
				}
			}

			// Generate OAuth connect URL if OAuth client is available
			connectURL := ""
			if h.serviceOAuthClient != nil {
				connectURL = h.serviceOAuthClient.GetConnectURL(name, returnURL)
			}

			services = append(services, ServiceSelectionData{
				Name:        name,
				DisplayName: displayName,
				Status:      status,
				ErrorMsg:    errorMsg,
				ConnectURL:  connectURL,
			})
		}
	}

	// Get message and type from query params
	message := r.URL.Query().Get("message")
	messageType := r.URL.Query().Get("type")
	if messageType == "" && message != "" {
		messageType = "error" // Default to error if type not specified
	}

	pageData := ServicesPageData{
		Services:    services,
		State:       url.QueryEscape(signedState),
		ReturnURL:   url.QueryEscape(returnURL),
		Message:     message,
		MessageType: messageType,
	}

	// Render template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := servicesPageTemplate.Execute(w, pageData); err != nil {
		log.LogError("Failed to render services page: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to render page")
	}
}

// CompleteOAuthHandler completes the original OAuth flow after service selection
func (h *AuthHandlers) CompleteOAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	signedState := r.URL.Query().Get("state")
	if signedState == "" {
		jsonwriter.WriteBadRequest(w, "Missing state parameter")
		return
	}

	upstreamOAuthState, err := h.verifyUpstreamOAuthState(signedState)
	if err != nil {
		log.LogError("Failed to verify OAuth state: %v", err)
		jsonwriter.WriteBadRequest(w, "Invalid or expired session")
		return
	}

	// Recreate the authorize request
	ctx := r.Context()
	client, err := h.storage.GetClient(ctx, upstreamOAuthState.ClientID)
	if err != nil {
		log.LogError("Failed to get client: %v", err)
		if errors.Is(err, fosite.ErrNotFound) {
			jsonwriter.WriteNotFound(w, "Client not found")
		} else {
			jsonwriter.WriteInternalServerError(w, "Failed to retrieve client")
		}
		return
	}

	// Create a new authorize request with the stored parameters
	ar := &fosite.AuthorizeRequest{
		ResponseTypes:        fosite.Arguments{upstreamOAuthState.ResponseType},
		RedirectURI:          &url.URL{},
		State:                upstreamOAuthState.State,
		HandledResponseTypes: fosite.Arguments{},
		Request: fosite.Request{
			ID:             crypto.GenerateSecureToken(),
			RequestedAt:    time.Now(),
			Client:         client,
			RequestedScope: upstreamOAuthState.Scopes,
			GrantedScope:   upstreamOAuthState.Scopes,
			Session:        &oauthsession.Session{DefaultSession: &fosite.DefaultSession{}},
		},
	}

	redirectURI, err := url.Parse(upstreamOAuthState.RedirectURI)
	if err != nil {
		log.LogError("Failed to parse redirect URI: %v", err)
		jsonwriter.WriteInternalServerError(w, "Invalid redirect URI")
		return
	}
	ar.RedirectURI = redirectURI

	// Create session with user info
	session := &oauthsession.Session{
		DefaultSession: &fosite.DefaultSession{
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().Add(h.authConfig.TokenTTL),
				fosite.RefreshToken: time.Now().Add(h.authConfig.TokenTTL * 2),
			},
		},
		UserInfo: upstreamOAuthState.UserInfo,
	}
	ar.SetSession(session)

	// Accept the authorization request
	response, err := h.oauthProvider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		log.LogError("Authorize response error: %v", err)
		h.oauthProvider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Write the response (redirects to Claude)
	h.oauthProvider.WriteAuthorizeResponse(ctx, w, ar, response)
}
