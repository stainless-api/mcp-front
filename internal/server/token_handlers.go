package server

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgellow/mcp-front/internal/auth"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
)

// TokenHandlers handles the web UI for token management
type TokenHandlers struct {
	tokenStore         storage.UserTokenStore
	mcpServers         map[string]*config.MCPClientConfig
	csrfTokens         sync.Map // Thread-safe CSRF token storage
	oauthEnabled       bool
	serviceOAuthClient *auth.ServiceOAuthClient
}

// NewTokenHandlers creates a new token handlers instance
func NewTokenHandlers(tokenStore storage.UserTokenStore, mcpServers map[string]*config.MCPClientConfig, oauthEnabled bool, serviceOAuthClient *auth.ServiceOAuthClient) *TokenHandlers {
	return &TokenHandlers{
		tokenStore:         tokenStore,
		mcpServers:         mcpServers,
		oauthEnabled:       oauthEnabled,
		serviceOAuthClient: serviceOAuthClient,
	}
}

// generateCSRFToken creates a new CSRF token
func (h *TokenHandlers) generateCSRFToken() (string, error) {
	token := crypto.GenerateSecureToken()
	if token == "" {
		return "", fmt.Errorf("failed to generate CSRF token")
	}
	h.csrfTokens.Store(token, true)
	return token, nil
}

// validateCSRFToken checks if a CSRF token is valid
func (h *TokenHandlers) validateCSRFToken(token string) bool {
	if _, exists := h.csrfTokens.LoadAndDelete(token); exists {
		// One-time use via LoadAndDelete
		return true
	}
	return false
}

// ListTokensHandler shows the token management page
func (h *TokenHandlers) ListTokensHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept GET
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	userEmail, ok := oauth.GetUserFromContext(r.Context())
	if !ok {
		jsonwriter.WriteUnauthorized(w, "Unauthorized")
		return
	}

	message := r.URL.Query().Get("message")
	messageType := r.URL.Query().Get("type")

	// Build service list
	var services []ServiceTokenData

	for name, serverConfig := range h.mcpServers {
		service := ServiceTokenData{
			Name:        name,
			DisplayName: name,
		}

		// Determine authentication type
		if serverConfig.RequiresUserToken {
			service.RequiresToken = true
			service.Instructions = fmt.Sprintf("Please create a %s API token", name)

			if serverConfig.UserAuthentication != nil {
				if serverConfig.UserAuthentication.DisplayName != "" {
					service.DisplayName = serverConfig.UserAuthentication.DisplayName
				}

				// Check if this service supports OAuth
				if serverConfig.UserAuthentication.Type == config.UserAuthTypeOAuth {
					service.SupportsOAuth = true
					service.Instructions = fmt.Sprintf("Connect your %s account via OAuth", service.DisplayName)

					// Generate OAuth connect URL if OAuth client is available
					if h.serviceOAuthClient != nil {
						service.ConnectURL = h.serviceOAuthClient.GetConnectURL(name, "/my/tokens")
					}

					// Check if OAuth is already connected
					storedToken, err := h.tokenStore.GetUserToken(r.Context(), userEmail, name)
					if err == nil && storedToken.Type == storage.TokenTypeOAuth {
						service.IsOAuthConnected = true
						service.HasToken = true
					}
				} else if serverConfig.UserAuthentication.Type == config.UserAuthTypeManual {
					if serverConfig.UserAuthentication.Instructions != "" {
						service.Instructions = serverConfig.UserAuthentication.Instructions
					}
					service.HelpURL = serverConfig.UserAuthentication.HelpURL

					// Check if manual token exists
					_, err := h.tokenStore.GetUserToken(r.Context(), userEmail, name)
					service.HasToken = err == nil
				}
				service.TokenFormat = serverConfig.UserAuthentication.TokenFormat
			} else {
				// No UserAuthentication config means manual token
				_, err := h.tokenStore.GetUserToken(r.Context(), userEmail, name)
				service.HasToken = err == nil
			}
		} else {
			// Determine if it's OAuth authenticated or uses bearer tokens
			if h.oauthEnabled {
				service.AuthType = "oauth"
			} else if serverConfig.Options != nil && len(serverConfig.Options.AuthTokens) > 0 {
				service.AuthType = "bearer"
			} else {
				service.AuthType = "none"
			}
		}

		services = append(services, service)
	}

	// Generate CSRF token
	csrfToken, err := h.generateCSRFToken()
	if err != nil {
		log.LogErrorWithFields("token", "Failed to generate CSRF token", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	// Render page
	data := TokenPageData{
		UserEmail:   userEmail,
		Services:    services,
		CSRFToken:   csrfToken,
		Message:     message,
		MessageType: messageType,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tokenPageTemplate.Execute(w, data); err != nil {
		log.LogErrorWithFields("token", "Failed to render token page", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
		jsonwriter.WriteInternalServerError(w, "Internal server error")
	}
}

// SetTokenHandler handles token submission
func (h *TokenHandlers) SetTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	userEmail, ok := oauth.GetUserFromContext(r.Context())
	if !ok {
		jsonwriter.WriteUnauthorized(w, "Unauthorized")
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		jsonwriter.WriteBadRequest(w, "Bad request")
		return
	}

	// Validate CSRF token
	csrfToken := r.FormValue("csrf_token")
	if !h.validateCSRFToken(csrfToken) {
		jsonwriter.WriteForbidden(w, "Invalid CSRF token")
		return
	}

	serviceName := r.FormValue("service")
	if serviceName == "" {
		jsonwriter.WriteBadRequest(w, "Service name is required")
		return
	}

	// Validate service exists and requires user token
	serviceConfig, exists := h.mcpServers[serviceName]
	if !exists || !serviceConfig.RequiresUserToken {
		jsonwriter.WriteNotFound(w, "Service not found")
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	if token == "" {
		redirectWithMessage(w, r, "Token cannot be empty", "error")
		return
	}

	// Security: Limit token length to prevent DoS
	const maxTokenLength = 4096
	if len(token) > maxTokenLength {
		redirectWithMessage(w, r, "Token is too long", "error")
		return
	}

	if serviceConfig.UserAuthentication != nil &&
		serviceConfig.UserAuthentication.Type == config.UserAuthTypeManual &&
		serviceConfig.UserAuthentication.ValidationRegex != nil {
		if !serviceConfig.UserAuthentication.ValidationRegex.MatchString(token) {
			var helpMsg string
			displayName := serviceName
			if serviceConfig.UserAuthentication.DisplayName != "" {
				displayName = serviceConfig.UserAuthentication.DisplayName
			}

			// Provide specific error messages based on common token patterns
			validation := serviceConfig.UserAuthentication.Validation
			switch {
			case validation == "^[A-Za-z0-9_-]+$":
				helpMsg = fmt.Sprintf("%s token must contain only letters, numbers, underscores, and hyphens", displayName)
			case strings.Contains(validation, "^[A-Fa-f0-9]{64}$"):
				helpMsg = fmt.Sprintf("%s token must be a 64-character hexadecimal string", displayName)
			case strings.Contains(serviceConfig.UserAuthentication.TokenFormat, "Bearer "):
				helpMsg = fmt.Sprintf("%s token should not include 'Bearer' prefix - just the token value", displayName)
			default:
				if serviceConfig.UserAuthentication.HelpURL != "" {
					helpMsg = fmt.Sprintf("Invalid %s token format. Please check the required format at %s",
						displayName, serviceConfig.UserAuthentication.HelpURL)
				} else {
					helpMsg = fmt.Sprintf("Invalid %s token format. Expected pattern: %s",
						displayName, validation)
				}
			}
			redirectWithMessage(w, r, helpMsg, "error")
			return
		}
	}

	// Create StoredToken for manual entry
	storedToken := &storage.StoredToken{
		Type:      storage.TokenTypeManual,
		Value:     token,
		UpdatedAt: time.Now(),
	}

	if err := h.tokenStore.SetUserToken(r.Context(), userEmail, serviceName, storedToken); err != nil {
		log.LogErrorWithFields("token", "Failed to store token", map[string]any{
			"error":   err.Error(),
			"user":    userEmail,
			"service": serviceName,
		})
		redirectWithMessage(w, r, "Failed to save token", "error")
		return
	}

	displayName := serviceName
	if serviceConfig.UserAuthentication != nil && serviceConfig.UserAuthentication.DisplayName != "" {
		displayName = serviceConfig.UserAuthentication.DisplayName
	}

	log.LogInfoWithFields("token", "User configured token", map[string]any{
		"user":    userEmail,
		"service": serviceName,
		"action":  "set_token",
	})
	redirectWithMessage(w, r, fmt.Sprintf("Token for %s saved successfully", displayName), "success")
}

// DeleteTokenHandler handles token deletion
func (h *TokenHandlers) DeleteTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST
	if r.Method != http.MethodPost {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	userEmail, ok := oauth.GetUserFromContext(r.Context())
	if !ok {
		jsonwriter.WriteUnauthorized(w, "Unauthorized")
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		jsonwriter.WriteBadRequest(w, "Bad request")
		return
	}

	// Validate CSRF token
	csrfToken := r.FormValue("csrf_token")
	if !h.validateCSRFToken(csrfToken) {
		jsonwriter.WriteForbidden(w, "Invalid CSRF token")
		return
	}

	serviceName := r.FormValue("service")
	if serviceName == "" {
		jsonwriter.WriteBadRequest(w, "Service name is required")
		return
	}

	serviceConfig, exists := h.mcpServers[serviceName]
	if !exists {
		jsonwriter.WriteNotFound(w, "Service not found")
		return
	}

	if err := h.tokenStore.DeleteUserToken(r.Context(), userEmail, serviceName); err != nil {
		log.LogErrorWithFields("token", "Failed to delete token", map[string]any{
			"error":   err.Error(),
			"user":    userEmail,
			"service": serviceName,
		})
		redirectWithMessage(w, r, "Failed to delete token", "error")
		return
	}

	displayName := serviceName
	if serviceConfig.UserAuthentication != nil && serviceConfig.UserAuthentication.DisplayName != "" {
		displayName = serviceConfig.UserAuthentication.DisplayName
	}

	log.LogInfoWithFields("token", "User deleted token", map[string]any{
		"user":    userEmail,
		"service": serviceName,
		"action":  "delete_token",
	})
	redirectWithMessage(w, r, fmt.Sprintf("Token for %s removed", displayName), "success")
}

// redirectWithMessage redirects back to the token list page with a message
func redirectWithMessage(w http.ResponseWriter, r *http.Request, message, messageType string) {
	http.Redirect(w, r, fmt.Sprintf("/my/tokens?message=%s&type=%s",
		strings.ReplaceAll(message, " ", "+"), messageType), http.StatusSeeOther)
}
