package cookie

import (
	"net/http"
	"time"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/log"
)

const sessionCookie = "mcp_session"

// SetSession sets a session cookie with appropriate security settings
func SetSession(w http.ResponseWriter, value string, maxAge time.Duration) {
	secure := !config.IsDev()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})

	log.LogTraceWithFields("cookie", "Session cookie set", map[string]any{
		"maxAge":   maxAge.String(),
		"secure":   secure,
		"sameSite": "Lax",
	})
}

// Clear removes a cookie by setting MaxAge to -1
func Clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// ClearSession removes the session cookie
func ClearSession(w http.ResponseWriter) {
	Clear(w, sessionCookie)
	log.LogTraceWithFields("cookie", "Session cookie cleared", nil)
}

// Get retrieves a cookie value from the request
func Get(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// GetSession retrieves the session cookie value
func GetSession(r *http.Request) (string, error) {
	return Get(r, sessionCookie)
}
