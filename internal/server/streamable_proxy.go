package server

import (
	"bytes"
	"context"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/dgellow/mcp-front/internal/config"
	"github.com/dgellow/mcp-front/internal/jsonrpc"
	"github.com/dgellow/mcp-front/internal/log"
)

// forwardStreamablePostToBackend handles POST requests for streamable-http transport
func forwardStreamablePostToBackend(ctx context.Context, w http.ResponseWriter, r *http.Request, config *config.MCPClientConfig) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.LogErrorWithFields("streamable_proxy", "Failed to read request body", map[string]any{
			"error": err.Error(),
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "Failed to read request")
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.URL, bytes.NewReader(body))
	if err != nil {
		log.LogErrorWithFields("streamable_proxy", "Failed to create backend request", map[string]any{
			"error": err.Error(),
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "Failed to create request")
		return
	}

	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))

	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	req.Header.Set("Accept", "application/json, text/event-stream")

	log.LogDebugWithFields("streamable_proxy", "Forwarding POST to backend", map[string]any{
		"backendURL": config.URL,
		"method":     r.Method,
		"headers":    config.Headers,
	})

	client := &http.Client{
		Timeout: config.Timeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.LogErrorWithFields("streamable_proxy", "Backend request failed", map[string]any{
			"error": err.Error(),
			"url":   config.URL,
		})
		jsonrpc.WriteError(w, nil, jsonrpc.InternalError, "backend request failed")
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "text/event-stream") {
		log.LogInfoWithFields("streamable_proxy", "Backend returned SSE stream", map[string]any{
			"status": resp.StatusCode,
		})

		for k, v := range resp.Header {
			if k == "Content-Type" || k == "Cache-Control" || k == "Connection" {
				w.Header()[k] = v
			}
		}

		w.WriteHeader(resp.StatusCode)

		flusher, ok := w.(http.Flusher)
		if !ok {
			log.LogError("Response writer doesn't support flushing")
			return
		}

		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					log.LogDebugWithFields("streamable_proxy", "Client disconnected", map[string]any{
						"error": writeErr.Error(),
					})
					return
				}
				flusher.Flush()
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				log.LogErrorWithFields("streamable_proxy", "Error reading SSE stream", map[string]any{
					"error": err.Error(),
				})
				return
			}
		}
	} else {
		w.WriteHeader(resp.StatusCode)

		maps.Copy(w.Header(), resp.Header)

		if _, err := io.Copy(w, resp.Body); err != nil {
			log.LogErrorWithFields("streamable_proxy", "Failed to copy response body", map[string]any{
				"error": err.Error(),
			})
		}
	}
}
