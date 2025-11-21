package sse

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// WriteMessage writes a SSE message to the response writer
func WriteMessage(w http.ResponseWriter, flusher http.Flusher, data any) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write SSE format
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
	flusher.Flush()

	return nil
}
