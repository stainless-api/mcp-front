package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/cookie"
	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/idp"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/session"
	"github.com/dgellow/mcp-front/internal/storage"
)

type AuthHandlers struct {
	authServer         *oauth.AuthorizationServer
	authConfig         config.OAuthAuthConfig
	idpProvider        idp.Provider
	storage            storage.Storage
	sessionEncryptor   crypto.Encryptor
	mcpServers         map[string]*config.MCPClientConfig
	oauthStateToken    crypto.TokenSigner
	serviceOAuthClient *auth.ServiceOAuthClient
}

type UpstreamOAuthState struct {
	Identity    idp.Identity `json:"identity"`
	ClientID    string       `json:"client_id"`
	RedirectURI string       `json:"redirect_uri"`
	Scopes      []string     `json:"scopes"`
	Audience    []string     `json:"audience"`
	State       string       `json:"state"`
}

func NewAuthHandlers(
	authServer *oauth.AuthorizationServer,
	authConfig config.OAuthAuthConfig,
	idpProvider idp.Provider,
	storage storage.Storage,
	sessionEncryptor crypto.Encryptor,
	mcpServers map[string]*config.MCPClientConfig,
	serviceOAuthClient *auth.ServiceOAuthClient,
) *AuthHandlers {
	return &AuthHandlers{
		authServer:         authServer,
		authConfig:         authConfig,
		idpProvider:        idpProvider,
		storage:            storage,
		sessionEncryptor:   sessionEncryptor,
		mcpServers:         mcpServers,
		oauthStateToken:    crypto.NewTokenSigner([]byte(authConfig.EncryptionKey), 10*time.Minute),
		serviceOAuthClient: serviceOAuthClient,
	}
}

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

func (h *AuthHandlers) ProtectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Protected resource metadata handler called: %s %s", r.Method, r.URL.Path)

	if !h.authConfig.DangerouslyAcceptIssuerAudience {
		jsonwriter.WriteNotFound(w, "Use /.well-known/oauth-protected-resource/{service} for per-service metadata")
		return
	}

	issuer := h.authConfig.Issuer
	log.LogWarnWithFields("oauth", "Serving base protected resource metadata (dangerouslyAcceptIssuerAudience enabled)", map[string]any{
		"issuer": issuer,
	})

	authzServerURL, err := oauth.AuthorizationServerMetadataURI(issuer)
	if err != nil {
		log.LogError("Failed to build protected resource metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	metadata := map[string]any{
		"resource":              issuer,
		"authorization_servers": []string{issuer},
		"_links": map[string]any{
			"oauth-authorization-server": map[string]string{
				"href": authzServerURL,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.LogError("Failed to encode protected resource metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
	}
}

func (h *AuthHandlers) ServiceProtectedResourceMetadataHandler(w http.ResponseWriter, r *http.Request) {
	serviceName := r.PathValue("service")
	if serviceName == "" {
		jsonwriter.WriteNotFound(w, "Service name required")
		return
	}

	log.Logf("Service protected resource metadata handler called for service: %s", serviceName)

	if _, exists := h.mcpServers[serviceName]; !exists {
		log.LogWarnWithFields("oauth", "Unknown service requested in metadata", map[string]any{
			"service": serviceName,
		})
		jsonwriter.WriteNotFound(w, fmt.Sprintf("Unknown service: %s", serviceName))
		return
	}

	metadata, err := oauth.ServiceProtectedResourceMetadata(h.authConfig.Issuer, serviceName)
	if err != nil {
		log.LogError("Failed to build service protected resource metadata: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.LogError("Failed to encode service protected resource metadata: %v", err)
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

	client, err := h.storage.GetClient(r.Context(), clientID)
	if err != nil {
		log.LogError("Failed to get client %s: %v", clientID, err)
		if errors.Is(err, storage.ErrClientNotFound) {
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

func (h *AuthHandlers) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Authorize handler called: %s %s", r.Method, r.URL.Path)

	stateParam := r.URL.Query().Get("state")
	if config.IsDev() && len(stateParam) == 0 {
		generatedState, err := crypto.GenerateSecureToken()
		if err != nil {
			log.LogError("Failed to generate state parameter: %v", err)
			jsonwriter.WriteInternalServerError(w, "Internal server error")
			return
		}
		log.LogWarn("Development mode: generating state parameter '%s' for buggy client", generatedState)
		q := r.URL.Query()
		q.Set("state", generatedState)
		r.URL.RawQuery = q.Encode()
		if r.Form == nil {
			_ = r.ParseForm()
		}
		r.Form.Set("state", generatedState)
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		jsonwriter.WriteBadRequest(w, "Missing client_id parameter")
		return
	}

	client, err := h.storage.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrClientNotFound) {
			jsonwriter.WriteBadRequest(w, "Unknown client_id")
		} else {
			jsonwriter.WriteInternalServerError(w, "Failed to retrieve client")
		}
		return
	}

	params, err := h.authServer.ValidateAuthorizeRequest(r, client)
	if err != nil {
		var oauthErr *oauth.OAuthError
		if errors.As(err, &oauthErr) {
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			oauth.WriteAuthorizeError(w, r, redirectURI, state, oauthErr)
		} else {
			jsonwriter.WriteBadRequest(w, err.Error())
		}
		return
	}

	signedParams, err := h.oauthStateToken.Sign(params)
	if err != nil {
		log.LogError("Failed to sign authorize params: %v", err)
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	authURL := h.idpProvider.AuthURL(signedParams)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *AuthHandlers) IDPCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.LogError("OAuth error: %s - %s", errMsg, errDesc)
		jsonwriter.WriteBadRequest(w, fmt.Sprintf("Authentication failed: %s", errMsg))
		return
	}

	if state == "" || code == "" {
		log.LogError("Missing state or code in callback")
		jsonwriter.WriteBadRequest(w, "Invalid callback parameters")
		return
	}

	var isBrowserFlow bool
	var returnURL string
	var authorizeParams *oauth.AuthorizeParams

	if strings.HasPrefix(state, "browser:") {
		isBrowserFlow = true
		stateToken := strings.TrimPrefix(state, "browser:")

		var browserState session.AuthorizationState
		if err := h.oauthStateToken.Verify(stateToken, &browserState); err != nil {
			log.LogError("Invalid browser state: %v", err)
			jsonwriter.WriteBadRequest(w, "Invalid state parameter")
			return
		}
		returnURL = browserState.ReturnURL
	} else {
		var params oauth.AuthorizeParams
		if err := h.oauthStateToken.Verify(state, &params); err != nil {
			log.LogError("Invalid or expired state: %v", err)
			jsonwriter.WriteBadRequest(w, "Invalid or expired authorization request")
			return
		}
		authorizeParams = &params
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	token, err := h.idpProvider.ExchangeCode(ctx, code)
	if err != nil {
		log.LogError("Failed to exchange code: %v", err)
		if !isBrowserFlow && authorizeParams != nil {
			oauth.WriteAuthorizeError(w, r, authorizeParams.RedirectURI, authorizeParams.State,
				oauth.NewOAuthError(oauth.ErrServerError, "Failed to exchange authorization code"))
		} else {
			jsonwriter.WriteInternalServerError(w, "Authentication failed")
		}
		return
	}

	identity, err := h.idpProvider.UserInfo(ctx, token)
	if err != nil {
		log.LogError("Failed to fetch user identity: %v", err)
		if !isBrowserFlow && authorizeParams != nil {
			oauth.WriteAuthorizeError(w, r, authorizeParams.RedirectURI, authorizeParams.State,
				oauth.NewOAuthError(oauth.ErrServerError, "Failed to fetch user identity"))
		} else {
			jsonwriter.WriteInternalServerError(w, "Authentication failed")
		}
		return
	}

	if err := h.validateAccess(identity); err != nil {
		log.LogError("Access denied: %v", err)
		if !isBrowserFlow && authorizeParams != nil {
			oauth.WriteAuthorizeError(w, r, authorizeParams.RedirectURI, authorizeParams.State,
				oauth.NewOAuthError(oauth.ErrAccessDenied, err.Error()))
		} else {
			jsonwriter.WriteForbidden(w, "Access denied")
		}
		return
	}

	log.Logf("User authenticated: %s", identity.Email)

	if isBrowserFlow {
		h.handleBrowserCallback(w, r, identity, returnURL)
	} else {
		h.handleOAuthClientCallback(ctx, w, r, authorizeParams, identity)
	}
}

func (h *AuthHandlers) handleBrowserCallback(w http.ResponseWriter, r *http.Request, identity *idp.Identity, returnURL string) {
	sessionDuration := 24 * time.Hour

	sessionData := session.BrowserCookie{
		Email:    identity.Email,
		Provider: identity.ProviderType,
		Expires:  time.Now().Add(sessionDuration),
	}

	jsonData, err := json.Marshal(sessionData)
	if err != nil {
		log.LogError("Failed to marshal session data: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to create session")
		return
	}

	encryptedData, err := h.sessionEncryptor.Encrypt(string(jsonData))
	if err != nil {
		log.LogError("Failed to encrypt session: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to create session")
		return
	}

	cookie.SetSession(w, encryptedData, sessionDuration)

	log.LogInfoWithFields("auth", "Browser SSO session created", map[string]any{
		"user":      identity.Email,
		"duration":  sessionDuration,
		"returnURL": returnURL,
	})

	http.Redirect(w, r, returnURL, http.StatusFound)
}

func (h *AuthHandlers) handleOAuthClientCallback(ctx context.Context, w http.ResponseWriter, r *http.Request, params *oauth.AuthorizeParams, identity *idp.Identity) {
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
		stateData, err := h.signUpstreamOAuthState(params, *identity)
		if err != nil {
			log.LogError("Failed to sign OAuth state: %v", err)
			oauth.WriteAuthorizeError(w, r, params.RedirectURI, params.State,
				oauth.NewOAuthError(oauth.ErrServerError, "Failed to prepare service authentication"))
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/oauth/services?state=%s", url.QueryEscape(stateData)), http.StatusFound)
		return
	}

	grant, err := h.authServer.IssueCode(params, *identity)
	if err != nil {
		log.LogError("Failed to issue authorization code: %v", err)
		oauth.WriteAuthorizeError(w, r, params.RedirectURI, params.State,
			oauth.NewOAuthError(oauth.ErrServerError, "Failed to issue authorization code"))
		return
	}

	if err := h.storage.StoreGrant(ctx, grant.Code, grant); err != nil {
		log.LogError("Failed to store grant: %v", err)
		oauth.WriteAuthorizeError(w, r, params.RedirectURI, params.State,
			oauth.NewOAuthError(oauth.ErrServerError, "Failed to store authorization grant"))
		return
	}

	redirectURL, _ := url.Parse(params.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", grant.Code)
	if params.State != "" {
		q.Set("state", params.State)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (h *AuthHandlers) TokenHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Token handler called: %s %s", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		oauth.WriteTokenError(w, http.StatusBadRequest, oauth.NewOAuthError(oauth.ErrInvalidRequest, "Failed to parse form"))
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")

	if clientID == "" {
		oauth.WriteTokenError(w, http.StatusBadRequest, oauth.NewOAuthError(oauth.ErrInvalidRequest, "Missing client_id"))
		return
	}

	client, err := h.storage.GetClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, storage.ErrClientNotFound) {
			oauth.WriteTokenError(w, http.StatusUnauthorized, oauth.NewOAuthError(oauth.ErrInvalidClient, "Unknown client"))
		} else {
			oauth.WriteTokenError(w, http.StatusInternalServerError, oauth.NewOAuthError(oauth.ErrServerError, "Failed to retrieve client"))
		}
		return
	}

	var pair *oauth.TokenPair

	switch grantType {
	case "authorization_code":
		code := r.FormValue("code")
		if code == "" {
			oauth.WriteTokenError(w, http.StatusBadRequest, oauth.NewOAuthError(oauth.ErrInvalidRequest, "Missing code"))
			return
		}

		grant, err := h.storage.ConsumeGrant(r.Context(), code)
		if err != nil {
			if errors.Is(err, storage.ErrGrantNotFound) {
				oauth.WriteTokenError(w, http.StatusBadRequest, oauth.NewOAuthError(oauth.ErrInvalidGrant, "Invalid or expired authorization code"))
			} else {
				oauth.WriteTokenError(w, http.StatusInternalServerError, oauth.NewOAuthError(oauth.ErrServerError, "Failed to retrieve grant"))
			}
			return
		}

		pair, err = h.authServer.ExchangeCode(grant, &oauth.ExchangeCodeRequest{
			RedirectURI:  r.FormValue("redirect_uri"),
			CodeVerifier: r.FormValue("code_verifier"),
			ClientSecret: r.FormValue("client_secret"),
		}, client)
		if err != nil {
			var oauthErr *oauth.OAuthError
			if errors.As(err, &oauthErr) {
				oauth.WriteTokenError(w, http.StatusBadRequest, oauthErr)
			} else {
				oauth.WriteTokenError(w, http.StatusInternalServerError, oauth.NewOAuthError(oauth.ErrServerError, err.Error()))
			}
			return
		}

	case "refresh_token":
		refreshToken := r.FormValue("refresh_token")
		if refreshToken == "" {
			oauth.WriteTokenError(w, http.StatusBadRequest, oauth.NewOAuthError(oauth.ErrInvalidRequest, "Missing refresh_token"))
			return
		}

		pair, err = h.authServer.RefreshTokens(refreshToken, client, &oauth.RefreshRequest{
			ClientSecret: r.FormValue("client_secret"),
		})
		if err != nil {
			var oauthErr *oauth.OAuthError
			if errors.As(err, &oauthErr) {
				oauth.WriteTokenError(w, http.StatusBadRequest, oauthErr)
			} else {
				oauth.WriteTokenError(w, http.StatusInternalServerError, oauth.NewOAuthError(oauth.ErrServerError, err.Error()))
			}
			return
		}

	default:
		oauth.WriteTokenError(w, http.StatusBadRequest, oauth.NewOAuthError(oauth.ErrUnsupportedGrantType, fmt.Sprintf("Unsupported grant_type: %s", grantType)))
		return
	}

	oauth.WriteTokenResponse(w, pair)
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

func (h *AuthHandlers) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Logf("Register handler called: %s %s", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	var metadata map[string]any
	if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
		jsonwriter.WriteBadRequest(w, "Invalid request body")
		return
	}

	redirectURIs, scopes, err := oauth.ParseClientRegistration(metadata)
	if err != nil {
		log.LogError("Client request parsing error: %v", err)
		jsonwriter.WriteBadRequest(w, err.Error())
		return
	}

	tokenEndpointAuthMethod := "none"
	var client *storage.Client
	var plaintextSecret string
	clientID, err := crypto.GenerateSecureToken()
	if err != nil {
		log.LogError("Failed to generate client ID: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to create client")
		return
	}

	if authMethod, ok := metadata["token_endpoint_auth_method"].(string); ok && authMethod == "client_secret_post" {
		plaintextSecret, err = crypto.GenerateSecureToken()
		if err != nil {
			log.LogError("Failed to generate client secret: %v", err)
			jsonwriter.WriteInternalServerError(w, "Failed to create client")
			return
		}
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

func (h *AuthHandlers) signUpstreamOAuthState(params *oauth.AuthorizeParams, identity idp.Identity) (string, error) {
	state := UpstreamOAuthState{
		Identity:    identity,
		ClientID:    params.ClientID,
		RedirectURI: params.RedirectURI,
		Scopes:      params.Scopes,
		Audience:    params.Audience,
		State:       params.State,
	}

	return h.oauthStateToken.Sign(state)
}

func (h *AuthHandlers) verifyUpstreamOAuthState(signedState string) (*UpstreamOAuthState, error) {
	var state UpstreamOAuthState
	if err := h.oauthStateToken.Verify(signedState, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (h *AuthHandlers) validateAccess(identity *idp.Identity) error {
	if len(h.authConfig.AllowedDomains) > 0 &&
		!slices.Contains(h.authConfig.AllowedDomains, identity.Domain) {
		return fmt.Errorf("domain '%s' is not allowed. Contact your administrator", identity.Domain)
	}
	if len(h.authConfig.IDP.AllowedOrgs) > 0 &&
		!hasOverlap(identity.Organizations, h.authConfig.IDP.AllowedOrgs) {
		return fmt.Errorf("user is not a member of any allowed organization. Contact your administrator")
	}
	return nil
}

func hasOverlap(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

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

	userEmail := upstreamOAuthState.Identity.Email

	returnURL := fmt.Sprintf("/oauth/services?state=%s", url.QueryEscape(signedState))

	var services []ServiceSelectionData
	for name, serverConfig := range h.mcpServers {
		if serverConfig.RequiresUserToken &&
			serverConfig.UserAuthentication != nil &&
			serverConfig.UserAuthentication.Type == config.UserAuthTypeOAuth {

			token, _ := h.storage.GetUserToken(r.Context(), userEmail, name)
			status := "not_connected"
			if token != nil {
				status = "connected"
			}

			displayName := name
			if serverConfig.UserAuthentication.DisplayName != "" {
				displayName = serverConfig.UserAuthentication.DisplayName
			}

			errorMsg := ""
			if r.URL.Query().Get("error") != "" && r.URL.Query().Get("service") == name {
				status = "error"
				errorMsg = r.URL.Query().Get("error_msg")
				if errorMsg == "" {
					errorMsg = r.URL.Query().Get("error_description")
				}
				if errorMsg == "" {
					errorMsg = "OAuth connection failed"
				}
			}

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

	message := r.URL.Query().Get("message")
	messageType := r.URL.Query().Get("type")
	if messageType == "" && message != "" {
		messageType = "error"
	}

	pageData := ServicesPageData{
		Services:    services,
		State:       url.QueryEscape(signedState),
		ReturnURL:   url.QueryEscape(returnURL),
		Message:     message,
		MessageType: messageType,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := servicesPageTemplate.Execute(w, pageData); err != nil {
		log.LogError("Failed to render services page: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to render page")
	}
}

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

	ctx := r.Context()

	params := &oauth.AuthorizeParams{
		ClientID:    upstreamOAuthState.ClientID,
		RedirectURI: upstreamOAuthState.RedirectURI,
		State:       upstreamOAuthState.State,
		Scopes:      upstreamOAuthState.Scopes,
		Audience:    upstreamOAuthState.Audience,
	}

	grant, err := h.authServer.IssueCode(params, upstreamOAuthState.Identity)
	if err != nil {
		log.LogError("Failed to issue authorization code: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to issue authorization code")
		return
	}

	if err := h.storage.StoreGrant(ctx, grant.Code, grant); err != nil {
		log.LogError("Failed to store grant: %v", err)
		jsonwriter.WriteInternalServerError(w, "Failed to store authorization grant")
		return
	}

	redirectURL, err := url.Parse(upstreamOAuthState.RedirectURI)
	if err != nil {
		log.LogError("Failed to parse redirect URI: %v", err)
		jsonwriter.WriteInternalServerError(w, "Invalid redirect URI")
		return
	}

	q := redirectURL.Query()
	q.Set("code", grant.Code)
	if upstreamOAuthState.State != "" {
		q.Set("state", upstreamOAuthState.State)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}
