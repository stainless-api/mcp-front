package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgellow/mcp-front/internal/crypto"
	"github.com/dgellow/mcp-front/internal/jsonrpc"
	"github.com/dgellow/mcp-front/internal/log"
	"github.com/dgellow/mcp-front/internal/oauth"
)

type Handler struct {
	server  *Server
	name    string
	baseURL string
	relay   *messageRelay
}

func NewHandler(name string, server *Server, baseURL string) *Handler {
	return &Handler{
		server:  server,
		name:    name,
		baseURL: baseURL,
		relay:   newMessageRelay(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/sse", "/" + h.name + "/sse":
		h.handleSSE(w, r)
	case "/message", "/" + h.name + "/message":
		h.handleMessage(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	userEmail, _ := oauth.GetUserFromContext(r.Context())
	if userEmail == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ch, unsub := h.relay.subscribe(userEmail)
	defer unsub()

	// Pre-warm backend connections and tool cache so tools/list responds fast.
	go h.server.PreWarm(userEmail)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.LogError("Response writer doesn't support flushing")
		return
	}

	sessionID, err := crypto.GenerateSecureToken()
	if err != nil {
		log.LogError("Failed to generate session ID: %v", err)
		return
	}

	endpointURL := fmt.Sprintf("%s/%s/message?sessionId=%s", strings.TrimSuffix(h.baseURL, "/"), h.name, sessionID)
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpointURL)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case data := <-ch:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (h *Handler) handleMessage(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("sessionId")

	userEmail, _ := oauth.GetUserFromContext(r.Context())
	authToken, _ := oauth.GetAuthTokenFromContext(r.Context())

	var request jsonrpc.Request
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.relayResponse(userEmail, jsonrpc.NewErrorResponse(nil, jsonrpc.NewError(jsonrpc.ParseError, "Invalid JSON")))
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.WriteHeader(http.StatusAccepted)

	go h.processMessage(userEmail, authToken, &request)
}

func (h *Handler) processMessage(userEmail string, authToken string, request *jsonrpc.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if authToken != "" {
		ctx = oauth.WithAuthToken(ctx, authToken)
	}

	var response *jsonrpc.Response

	switch request.Method {
	case "initialize":
		result := h.server.HandleInitialize(userEmail)
		response = jsonrpc.NewResponse(request.ID, result)
	case "tools/list":
		tools, err := h.server.HandleToolsList(ctx, userEmail)
		if err != nil {
			response = jsonrpc.NewErrorResponse(request.ID, jsonrpc.NewError(jsonrpc.InternalError, err.Error()))
		} else {
			response = jsonrpc.NewResponse(request.ID, map[string]any{"tools": tools})
		}
	case "tools/call":
		response = h.processToolCall(ctx, request, userEmail)
	default:
		response = jsonrpc.NewErrorResponse(request.ID, jsonrpc.NewError(jsonrpc.MethodNotFound, "Method not found"))
	}

	h.relayResponse(userEmail, response)
}

func (h *Handler) processToolCall(ctx context.Context, req *jsonrpc.Request, userEmail string) *jsonrpc.Response {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonrpc.NewErrorResponse(req.ID, jsonrpc.NewError(jsonrpc.InvalidParams, "Invalid parameters"))
	}

	result, err := h.server.HandleToolCall(ctx, userEmail, params.Name, params.Arguments)
	if err != nil {
		return jsonrpc.NewErrorResponse(req.ID, jsonrpc.NewError(jsonrpc.InternalError, err.Error()))
	}

	return jsonrpc.NewResponse(req.ID, result)
}

func (h *Handler) relayResponse(userEmail string, response *jsonrpc.Response) {
	data, err := json.Marshal(response)
	if err != nil {
		log.LogError("Failed to marshal JSON-RPC response: %v", err)
		return
	}
	h.relay.publish(userEmail, data)
}

// messageRelay distributes JSON-RPC responses from POST handlers to active SSE connections.
type messageRelay struct {
	mu   sync.Mutex
	subs map[string][]chan []byte
}

func newMessageRelay() *messageRelay {
	return &messageRelay{subs: make(map[string][]chan []byte)}
}

func (r *messageRelay) subscribe(userEmail string) (chan []byte, func()) {
	ch := make(chan []byte, 32)
	r.mu.Lock()
	r.subs[userEmail] = append(r.subs[userEmail], ch)
	r.mu.Unlock()
	return ch, func() {
		r.mu.Lock()
		subs := r.subs[userEmail]
		for i, s := range subs {
			if s == ch {
				r.subs[userEmail] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		if len(r.subs[userEmail]) == 0 {
			delete(r.subs, userEmail)
		}
		r.mu.Unlock()
	}
}

func (r *messageRelay) publish(userEmail string, data []byte) {
	r.mu.Lock()
	subs := make([]chan []byte, len(r.subs[userEmail]))
	copy(subs, r.subs[userEmail])
	r.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- data:
		default:
		}
	}
}
