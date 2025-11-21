package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dgellow/mcp-front/internal/adminauth"
	"github.com/dgellow/mcp-front/internal/client"
	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/crypto"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
	"github.com/dgellow/mcp-front/internal/storage"
)

// AdminHandlers handles the admin UI
type AdminHandlers struct {
	storage        storage.Storage
	config         config.Config
	sessionManager *client.StdioSessionManager
	encryptionKey  []byte // For HMAC-based CSRF tokens
}

// NewAdminHandlers creates a new admin handlers instance
func NewAdminHandlers(storage storage.Storage, config config.Config, sessionManager *client.StdioSessionManager, encryptionKey string) *AdminHandlers {
	return &AdminHandlers{
		storage:        storage,
		config:         config,
		sessionManager: sessionManager,
		encryptionKey:  []byte(encryptionKey),
	}
}

// generateCSRFToken creates a new HMAC-based CSRF token
func (h *AdminHandlers) generateCSRFToken() (string, error) {
	// Generate random nonce
	nonce := crypto.GenerateSecureToken()
	if nonce == "" {
		return "", fmt.Errorf("failed to generate nonce")
	}

	// Add timestamp (Unix seconds)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create data to sign: nonce:timestamp
	data := nonce + ":" + timestamp

	// Sign with HMAC
	signature := crypto.SignData(data, h.encryptionKey)

	// Return format: nonce:timestamp:signature
	return fmt.Sprintf("%s:%s:%s", nonce, timestamp, signature), nil
}

// validateCSRFToken checks if a CSRF token is valid
func (h *AdminHandlers) validateCSRFToken(token string) bool {
	// Parse token format: nonce:timestamp:signature
	parts := strings.SplitN(token, ":", 3)
	if len(parts) != 3 {
		log.LogDebug("Invalid CSRF token format")
		return false
	}

	nonce := parts[0]
	timestampStr := parts[1]
	signature := parts[2]

	// Verify timestamp (15 minute expiry)
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		log.LogDebug("Invalid CSRF token timestamp: %v", err)
		return false
	}

	now := time.Now().Unix()
	if now-timestamp > 900 { // 15 minutes
		log.LogDebug("CSRF token expired")
		return false
	}

	// Verify HMAC signature
	data := nonce + ":" + timestampStr
	if !crypto.ValidateSignedData(data, signature, h.encryptionKey) {
		log.LogDebug("Invalid CSRF token signature")
		return false
	}

	return true
}

// DashboardHandler shows the admin dashboard
func (h *AdminHandlers) DashboardHandler(w http.ResponseWriter, r *http.Request) {
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

	// Double-check admin status
	if !adminauth.IsAdmin(r.Context(), userEmail, h.config.Proxy.Admin, h.storage) {
		jsonwriter.WriteForbidden(w, "Forbidden")
		return
	}

	// Get current tab from query param
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "users"
	}

	// Get message from query params
	message := r.URL.Query().Get("message")
	messageType := r.URL.Query().Get("type")

	// Load all data
	rawUsers, err := h.storage.GetAllUsers(r.Context())
	if err != nil {
		log.LogErrorWithFields("admin", "Failed to get users", map[string]any{
			"error": err.Error(),
		})
		rawUsers = []storage.UserInfo{} // Empty list on error
	}

	// Convert to UserInfoWithAdminType
	users := make([]UserInfoWithAdminType, len(rawUsers))
	for i, user := range rawUsers {
		users[i] = UserInfoWithAdminType{
			UserInfo:      user,
			IsConfigAdmin: adminauth.IsConfigAdmin(user.Email, h.config.Proxy.Admin),
		}
	}

	sessions, err := h.storage.GetActiveSessions(r.Context())
	if err != nil {
		log.LogErrorWithFields("admin", "Failed to get sessions", map[string]any{
			"error": err.Error(),
		})
		sessions = []storage.ActiveSession{} // Empty list on error
	}

	currentLogLevel := log.GetLogLevel()

	// Generate CSRF token
	csrfToken, err := h.generateCSRFToken()
	if err != nil {
		log.LogErrorWithFields("admin", "Failed to generate CSRF token", map[string]any{
			"error": err.Error(),
		})
		jsonwriter.WriteInternalServerError(w, "Internal server error")
		return
	}

	// Render page
	data := AdminPageData{
		UserEmail:   userEmail,
		ActiveTab:   tab,
		Users:       users,
		Sessions:    sessions,
		LogLevel:    currentLogLevel,
		CSRFToken:   csrfToken,
		Message:     message,
		MessageType: messageType,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := adminPageTemplate.Execute(w, data); err != nil {
		log.LogErrorWithFields("admin", "Failed to render admin page", map[string]any{
			"error": err.Error(),
		})
		jsonwriter.WriteInternalServerError(w, "Internal server error")
	}
}

// UserActionHandler handles user management actions
func (h *AdminHandlers) UserActionHandler(w http.ResponseWriter, r *http.Request) {
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

	// Double-check admin status
	if !adminauth.IsAdmin(r.Context(), userEmail, h.config.Proxy.Admin, h.storage) {
		jsonwriter.WriteForbidden(w, "Forbidden")
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		jsonwriter.WriteBadRequest(w, "Bad request")
		return
	}

	// Validate CSRF
	if !h.validateCSRFToken(r.FormValue("csrf_token")) {
		jsonwriter.WriteForbidden(w, "Invalid CSRF token")
		return
	}

	action := r.FormValue("action")
	targetEmail := r.FormValue("user_email")

	if targetEmail == "" {
		jsonwriter.WriteBadRequest(w, "Missing user_email")
		return
	}

	var message string
	var messageType string = "success"

	switch action {
	case "toggle":
		// Get current status
		users, err := h.storage.GetAllUsers(r.Context())
		if err != nil {
			message = "Failed to get user status"
			messageType = "error"
		} else {
			var currentEnabled bool
			for _, u := range users {
				if u.Email == targetEmail {
					currentEnabled = u.Enabled
					break
				}
			}
			// Toggle status
			if err := h.storage.UpdateUserStatus(r.Context(), targetEmail, !currentEnabled); err != nil {
				message = fmt.Sprintf("Failed to update user: %v", err)
				messageType = "error"
			} else {
				if currentEnabled {
					message = fmt.Sprintf("User %s disabled", targetEmail)
					// Audit log
					log.LogInfoWithFields("admin", "User disabled", map[string]any{
						"admin_email":  userEmail,
						"target_email": targetEmail,
						"action":       "disable",
					})
				} else {
					message = fmt.Sprintf("User %s enabled", targetEmail)
					// Audit log
					log.LogInfoWithFields("admin", "User enabled", map[string]any{
						"admin_email":  userEmail,
						"target_email": targetEmail,
						"action":       "enable",
					})
				}
			}
		}

	case "delete":
		if err := h.storage.DeleteUser(r.Context(), targetEmail); err != nil {
			message = fmt.Sprintf("Failed to delete user: %v", err)
			messageType = "error"
		} else {
			message = fmt.Sprintf("User %s deleted", targetEmail)
			// Audit log
			log.LogInfoWithFields("admin", "User deleted", map[string]any{
				"admin_email":  userEmail,
				"target_email": targetEmail,
				"action":       "delete",
			})
		}

	case "promote":
		// Check if user exists
		users, err := h.storage.GetAllUsers(r.Context())
		if err != nil {
			message = "Failed to verify user existence"
			messageType = "error"
		} else {
			userExists := false
			alreadyAdmin := false
			for _, u := range users {
				if u.Email == targetEmail {
					userExists = true
					alreadyAdmin = u.IsAdmin
					break
				}
			}

			if !userExists {
				message = fmt.Sprintf("User %s not found", targetEmail)
				messageType = "error"
			} else if alreadyAdmin {
				message = fmt.Sprintf("User %s is already an admin", targetEmail)
				messageType = "error"
			} else {
				if err := h.storage.SetUserAdmin(r.Context(), targetEmail, true); err != nil {
					message = fmt.Sprintf("Failed to promote user: %v", err)
					messageType = "error"
				} else {
					message = fmt.Sprintf("User %s promoted to admin", targetEmail)
					// Audit log
					log.LogInfoWithFields("admin", "User promoted to admin", map[string]any{
						"admin_email":  userEmail,
						"target_email": targetEmail,
						"action":       "promote",
					})
				}
			}
		}

	case "demote":
		// Prevent demoting yourself
		if targetEmail == userEmail {
			message = "Cannot demote yourself"
			messageType = "error"
		} else if adminauth.IsConfigAdmin(targetEmail, h.config.Proxy.Admin) {
			// Prevent demoting config admins
			message = "Cannot demote config-defined admins"
			messageType = "error"
		} else {
			if err := h.storage.SetUserAdmin(r.Context(), targetEmail, false); err != nil {
				message = fmt.Sprintf("Failed to demote user: %v", err)
				messageType = "error"
			} else {
				message = fmt.Sprintf("User %s demoted from admin", targetEmail)
				// Audit log
				log.LogInfoWithFields("admin", "User demoted from admin", map[string]any{
					"admin_email":  userEmail,
					"target_email": targetEmail,
					"action":       "demote",
				})
			}
		}

	default:
		message = "Unknown action"
		messageType = "error"
	}

	// Redirect back to admin page with message
	http.Redirect(w, r, fmt.Sprintf("/admin?tab=users&message=%s&type=%s",
		url.QueryEscape(message), messageType), http.StatusSeeOther)
}

// SessionActionHandler handles session management actions
func (h *AdminHandlers) SessionActionHandler(w http.ResponseWriter, r *http.Request) {
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

	// Double-check admin status
	if !adminauth.IsAdmin(r.Context(), userEmail, h.config.Proxy.Admin, h.storage) {
		jsonwriter.WriteForbidden(w, "Forbidden")
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		jsonwriter.WriteBadRequest(w, "Bad request")
		return
	}

	// Validate CSRF
	if !h.validateCSRFToken(r.FormValue("csrf_token")) {
		jsonwriter.WriteForbidden(w, "Invalid CSRF token")
		return
	}

	action := r.FormValue("action")
	sessionID := r.FormValue("session_id")

	if sessionID == "" {
		jsonwriter.WriteBadRequest(w, "Missing session_id")
		return
	}

	var message string
	var messageType string = "success"

	switch action {
	case "revoke":
		// First get session details to revoke from session manager
		sessions, err := h.storage.GetActiveSessions(r.Context())
		if err == nil {
			for _, s := range sessions {
				if s.SessionID == sessionID {
					// Remove from session manager
					key := client.SessionKey{
						UserEmail:  s.UserEmail,
						ServerName: s.ServerName,
						SessionID:  s.SessionID,
					}
					h.sessionManager.RemoveSession(key)
					break
				}
			}
		}

		// Remove from storage
		if err := h.storage.RevokeSession(r.Context(), sessionID); err != nil {
			message = fmt.Sprintf("Failed to revoke session: %v", err)
			messageType = "error"
		} else {
			message = "Session revoked"
			// Audit log
			log.LogInfoWithFields("admin", "Session revoked", map[string]any{
				"admin_email": userEmail,
				"session_id":  sessionID,
				"action":      "revoke_session",
			})
		}

	default:
		message = "Unknown action"
		messageType = "error"
	}

	// Redirect back to admin page with message
	http.Redirect(w, r, fmt.Sprintf("/admin?tab=sessions&message=%s&type=%s",
		url.QueryEscape(message), messageType), http.StatusSeeOther)
}

// LoggingActionHandler handles logging configuration changes
func (h *AdminHandlers) LoggingActionHandler(w http.ResponseWriter, r *http.Request) {
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

	// Double-check admin status
	if !adminauth.IsAdmin(r.Context(), userEmail, h.config.Proxy.Admin, h.storage) {
		jsonwriter.WriteForbidden(w, "Forbidden")
		return
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		jsonwriter.WriteBadRequest(w, "Bad request")
		return
	}

	// Validate CSRF
	if !h.validateCSRFToken(r.FormValue("csrf_token")) {
		jsonwriter.WriteForbidden(w, "Invalid CSRF token")
		return
	}

	logLevel := r.FormValue("log_level")
	if logLevel == "" {
		jsonwriter.WriteBadRequest(w, "Missing log_level")
		return
	}

	var message string
	var messageType string = "success"

	// Update log level
	if err := log.SetLogLevel(logLevel); err != nil {
		message = fmt.Sprintf("Failed to set log level: %v", err)
		messageType = "error"
	} else {
		message = fmt.Sprintf("Log level changed to %s", logLevel)

		// Log the change at INFO level
		log.LogInfoWithFields("admin", "Log level changed by admin", map[string]any{
			"new_level": logLevel,
			"admin":     userEmail,
		})
	}

	// Redirect back to admin page with message
	http.Redirect(w, r, fmt.Sprintf("/admin?tab=logging&message=%s&type=%s",
		url.QueryEscape(message), messageType), http.StatusSeeOther)
}

// AdminPageData represents the data for the admin page template
type AdminPageData struct {
	UserEmail   string
	ActiveTab   string
	Users       []UserInfoWithAdminType
	Sessions    []storage.ActiveSession
	LogLevel    string
	CSRFToken   string
	Message     string
	MessageType string
}

// UserInfoWithAdminType extends UserInfo with admin type information
type UserInfoWithAdminType struct {
	storage.UserInfo
	IsConfigAdmin bool // True if admin is defined in config
}
