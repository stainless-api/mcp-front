package json

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteUnauthorizedRFC9728(t *testing.T) {
	tests := []struct {
		name                         string
		message                      string
		protectedResourceMetadataURI string
		wantHeader                   string
		wantStatus                   int
	}{
		{
			name:                         "with resource metadata URI",
			message:                      "Invalid token",
			protectedResourceMetadataURI: "https://example.com/.well-known/oauth-protected-resource",
			wantHeader:                   `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			wantStatus:                   http.StatusUnauthorized,
		},
		{
			name:                         "without resource metadata URI",
			message:                      "Invalid token",
			protectedResourceMetadataURI: "",
			wantHeader:                   "",
			wantStatus:                   http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			WriteUnauthorizedRFC9728(w, tt.message, tt.protectedResourceMetadataURI)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %v, want %v", w.Code, tt.wantStatus)
			}

			gotHeader := w.Header().Get("WWW-Authenticate")
			if gotHeader != tt.wantHeader {
				t.Errorf("WWW-Authenticate header = %q, want %q", gotHeader, tt.wantHeader)
			}

			// Check that response contains error message
			body := w.Body.String()
			if body == "" {
				t.Error("expected non-empty response body")
			}
		})
	}
}

func TestWriteUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()

	WriteUnauthorized(w, "Test error")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %v, want %v", w.Code, http.StatusUnauthorized)
	}

	// Should not have WWW-Authenticate header
	if header := w.Header().Get("WWW-Authenticate"); header != "" {
		t.Errorf("unexpected WWW-Authenticate header: %q", header)
	}
}

func TestEscapeQuotedString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no special characters",
			input: "simple-realm",
			want:  "simple-realm",
		},
		{
			name:  "with double quote",
			input: `realm"with"quotes`,
			want:  `realm\"with\"quotes`,
		},
		{
			name:  "with backslash",
			input: `realm\with\backslash`,
			want:  `realm\\with\\backslash`,
		},
		{
			name:  "with both",
			input: `realm\"mixed`,
			want:  `realm\\\"mixed`,
		},
		{
			name:  "URL with protocol",
			input: "https://example.com/.well-known/oauth-protected-resource",
			want:  "https://example.com/.well-known/oauth-protected-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeQuotedString(tt.input)
			if got != tt.want {
				t.Errorf("escapeQuotedString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteUnauthorizedRFC9728_Escaping(t *testing.T) {
	w := httptest.NewRecorder()

	WriteUnauthorizedRFC9728(w, "Invalid token", `https://example.com/path"with"quotes`)

	wantHeader := `Bearer resource_metadata="https://example.com/path\"with\"quotes"`
	gotHeader := w.Header().Get("WWW-Authenticate")
	if gotHeader != wantHeader {
		t.Errorf("WWW-Authenticate header = %q, want %q", gotHeader, wantHeader)
	}
}
