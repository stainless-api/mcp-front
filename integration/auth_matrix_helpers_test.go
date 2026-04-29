package integration

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authMatrixCase is one row in the auth matrix for a given deployment.
type authMatrixCase struct {
	name           string
	authHeader     string // "" → no Authorization header
	wantStatus     int
	wantWWWAuthEq  string // exact match if non-empty
	wantWWWAuthSub string // substring match if non-empty (used when only fragment is stable)
	wantNoWWWAuth  bool   // assert WWW-Authenticate header is empty
}

// runAuthMatrix executes a list of authMatrixCases against routeURL.
//
// Contract:
//   - 200 cases assert Content-Type: text/event-stream (proves the request
//     reached the MCP handler, not just a middleware short-circuit), and
//     assert WWW-Authenticate is empty.
//   - 401 cases REQUIRE exactly one of wantWWWAuthEq, wantWWWAuthSub, or
//     wantNoWWWAuth to be set — a 401 without an explicit challenge assertion
//     is a test bug, not a passing test.
func runAuthMatrix(t *testing.T, routeURL string, cases []authMatrixCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.wantStatus == http.StatusUnauthorized {
				set := 0
				if c.wantWWWAuthEq != "" {
					set++
				}
				if c.wantWWWAuthSub != "" {
					set++
				}
				if c.wantNoWWWAuth {
					set++
				}
				require.Equalf(t, 1, set,
					"401 case %q must set exactly one of wantWWWAuthEq / wantWWWAuthSub / wantNoWWWAuth (got %d)", c.name, set)
			}

			req, err := http.NewRequest("GET", routeURL, nil)
			require.NoError(t, err)
			if c.authHeader != "" {
				req.Header.Set("Authorization", c.authHeader)
			}
			req.Header.Set("Accept", "text/event-stream")

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, c.wantStatus, resp.StatusCode, "status code")

			gotHeader := resp.Header.Get("WWW-Authenticate")
			switch {
			case c.wantNoWWWAuth:
				assert.Empty(t, gotHeader, "WWW-Authenticate must be empty")
			case c.wantWWWAuthEq != "":
				assert.Equal(t, c.wantWWWAuthEq, gotHeader, "WWW-Authenticate exact match")
			case c.wantWWWAuthSub != "":
				assert.Contains(t, gotHeader, c.wantWWWAuthSub, "WWW-Authenticate substring")
			}

			if c.wantStatus == http.StatusOK {
				assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"),
					"200 should be SSE response from MCP handler")
				assert.Empty(t, resp.Header.Get("WWW-Authenticate"),
					"200 must not carry a WWW-Authenticate challenge")
			}
		})
	}
}

// basicHeader builds a Basic auth header for username:password.
func basicHeader(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// rfc9728BearerHeader is the expected WWW-Authenticate value for a 401 from
// the RequireAuth gate when OAuth is enabled, given a service path.
//
// Format per RFC 9728 Section 5.1: Bearer resource_metadata="<uri>"
// where the URI is built by oauth.ServiceProtectedResourceMetadataURI.
func rfc9728BearerHeader(issuer, serviceName string) string {
	uri := strings.TrimRight(issuer, "/") + "/.well-known/oauth-protected-resource/" + serviceName
	return `Bearer resource_metadata="` + uri + `"`
}
