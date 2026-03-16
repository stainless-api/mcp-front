package server

import (
	"context"
	"net/http"
	"time"

	"github.com/dgellow/mcp-front/internal/gateway"
	jsonwriter "github.com/dgellow/mcp-front/internal/json"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
)

// ToolsPageData represents the data for the tools listing page.
type ToolsPageData struct {
	UserEmail    string
	TotalTools   int
	ServiceCount int
	Services     []gateway.ServiceTools
	Error        string
}

// ToolsHandler serves the gateway tools listing page.
type ToolsHandler struct {
	gatewayServer *gateway.Server
}

// NewToolsHandler creates a new tools handler.
func NewToolsHandler(gatewayServer *gateway.Server) *ToolsHandler {
	return &ToolsHandler{gatewayServer: gatewayServer}
}

func (h *ToolsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonwriter.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}

	userEmail, _ := oauth.GetUserFromContext(r.Context())
	if userEmail == "" {
		jsonwriter.WriteUnauthorized(w, "Authentication required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	services, err := h.gatewayServer.ListToolsByService(ctx, userEmail)

	data := ToolsPageData{
		UserEmail: userEmail,
	}

	if err != nil {
		log.LogErrorWithFields("tools", "Failed to list tools", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
		data.Error = err.Error()
	} else {
		data.Services = services
		data.ServiceCount = len(services)
		for _, svc := range services {
			data.TotalTools += len(svc.Tools)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := toolsPageTemplate.Execute(w, data); err != nil {
		log.LogErrorWithFields("tools", "Failed to render tools page", map[string]any{
			"error": err.Error(),
			"user":  userEmail,
		})
	}
}
