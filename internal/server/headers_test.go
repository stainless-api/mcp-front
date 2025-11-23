package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCopyRequestHeaders(t *testing.T) {
	t.Run("copies allowed headers", func(t *testing.T) {
		src := http.Header{
			"User-Agent":      []string{"test-agent"},
			"Accept-Language": []string{"en-US"},
			"Content-Type":    []string{"application/json"},
			"X-Custom-Header": []string{"custom-value"},
		}

		dst := http.Header{}
		copyRequestHeaders(dst, src)

		assert.Equal(t, "test-agent", dst.Get("User-Agent"))
		assert.Equal(t, "en-US", dst.Get("Accept-Language"))
		assert.Equal(t, "application/json", dst.Get("Content-Type"))
		assert.Equal(t, "custom-value", dst.Get("X-Custom-Header"))
	})

	t.Run("strips hop-by-hop headers", func(t *testing.T) {
		src := http.Header{
			"Connection": []string{"keep-alive"},
			"Upgrade":    []string{"websocket"},
			"Host":       []string{"example.com"},
			"User-Agent": []string{"test-agent"},
		}

		dst := http.Header{}
		copyRequestHeaders(dst, src)

		assert.Empty(t, dst.Get("Connection"))
		assert.Empty(t, dst.Get("Upgrade"))
		assert.Empty(t, dst.Get("Host"))
		assert.Equal(t, "test-agent", dst.Get("User-Agent"))
	})

	t.Run("strips sensitive credentials", func(t *testing.T) {
		src := http.Header{
			"Authorization": []string{"Bearer mcp-front-oauth-token"},
			"Cookie":        []string{"session=abc123"},
			"User-Agent":    []string{"test-agent"},
		}

		dst := http.Header{}
		copyRequestHeaders(dst, src)

		assert.Empty(t, dst.Get("Authorization"), "Authorization should be stripped (mcp-front's OAuth token)")
		assert.Empty(t, dst.Get("Cookie"), "Cookie should be stripped (mcp-front's session)")
		assert.Equal(t, "test-agent", dst.Get("User-Agent"))
	})

	t.Run("handles empty source headers", func(t *testing.T) {
		src := http.Header{}
		dst := http.Header{}

		copyRequestHeaders(dst, src)

		assert.Empty(t, dst)
	})

	t.Run("preserves existing destination headers not in source", func(t *testing.T) {
		src := http.Header{
			"User-Agent": []string{"test-agent"},
		}

		dst := http.Header{
			"X-Existing": []string{"existing-value"},
		}

		copyRequestHeaders(dst, src)

		assert.Equal(t, "test-agent", dst.Get("User-Agent"))
		assert.Equal(t, "existing-value", dst.Get("X-Existing"))
	})

	t.Run("comprehensive security test", func(t *testing.T) {
		src := http.Header{
			// Should be stripped
			"Authorization": []string{"Bearer oauth-token"},
			"Cookie":        []string{"session=secret"},
			"Connection":    []string{"keep-alive"},
			"Upgrade":       []string{"websocket"},
			"Host":          []string{"mcp-front.example.com"},

			// Should be copied
			"User-Agent":      []string{"Mozilla/5.0"},
			"Accept":          []string{"text/event-stream"},
			"Accept-Language": []string{"en-US,en;q=0.9"},
			"Content-Type":    []string{"application/json"},
			"X-Request-Id":    []string{"req-123"},
			"X-Custom":        []string{"custom-value"},
		}

		dst := http.Header{}
		copyRequestHeaders(dst, src)

		// Verify sensitive headers are NOT copied
		assert.Empty(t, dst.Get("Authorization"))
		assert.Empty(t, dst.Get("Cookie"))
		assert.Empty(t, dst.Get("Connection"))
		assert.Empty(t, dst.Get("Upgrade"))
		assert.Empty(t, dst.Get("Host"))

		// Verify safe headers ARE copied
		assert.Equal(t, "Mozilla/5.0", dst.Get("User-Agent"))
		assert.Equal(t, "text/event-stream", dst.Get("Accept"))
		assert.Equal(t, "en-US,en;q=0.9", dst.Get("Accept-Language"))
		assert.Equal(t, "application/json", dst.Get("Content-Type"))
		assert.Equal(t, "req-123", dst.Get("X-Request-Id"))
		assert.Equal(t, "custom-value", dst.Get("X-Custom"))
	})
}
