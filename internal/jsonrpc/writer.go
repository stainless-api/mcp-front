package jsonrpc

import (
	"encoding/json"
	"net/http"

	"github.com/stainless-api/mcp-front/internal/log"
)

// WriteResponse writes a JSON-RPC response to the http.ResponseWriter
func WriteResponse(w http.ResponseWriter, response *Response) error {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.LogError("Failed to encode JSON-RPC response: %v", err)
		return err
	}
	return nil
}

// WriteResult writes a successful JSON-RPC response
func WriteResult(w http.ResponseWriter, id any, result any) error {
	return WriteResponse(w, NewResponse(id, result))
}

// WriteError writes a JSON-RPC error response with OK status
func WriteError(w http.ResponseWriter, id any, code int, message string) {
	WriteErrorWithStatus(w, id, code, message, http.StatusOK)
}

// WriteErrorWithStatus writes a JSON-RPC error response with custom HTTP status
func WriteErrorWithStatus(w http.ResponseWriter, id any, code int, message string, httpStatus int) {
	response := NewErrorResponse(id, NewError(code, message))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.LogError("Failed to encode JSON-RPC error response: %v", err)
	}
}

// WriteStandardError writes a JSON-RPC error using standard error messages
func WriteStandardError(w http.ResponseWriter, id any, code int) {
	WriteErrorWithStatus(w, id, code, errorMessages[code], http.StatusOK)
}

// WriteInvalidJSON writes a parse error response for invalid JSON
func WriteInvalidJSON(w http.ResponseWriter) {
	// Invalid JSON means we can't determine the ID, so it's null
	WriteErrorWithStatus(w, nil, ParseError, "Invalid JSON", http.StatusBadRequest)
}
