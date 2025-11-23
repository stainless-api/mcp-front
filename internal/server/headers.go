package server

import "net/http"

// copyRequestHeaders copies relevant headers from the client request to the backend request,
// excluding hop-by-hop headers and sensitive credentials.
//
// Excluded headers:
//   - Connection, Upgrade, Host: hop-by-hop headers that shouldn't be forwarded
//   - Authorization: mcp-front's OAuth token, replaced by config.Headers if needed
//   - Cookie: mcp-front's session cookie, backend-specific
func copyRequestHeaders(dst, src http.Header) {
	for k, v := range src {
		if k == "Connection" || k == "Upgrade" || k == "Host" ||
			k == "Authorization" || k == "Cookie" {
			continue
		}
		dst[k] = v
	}
}
