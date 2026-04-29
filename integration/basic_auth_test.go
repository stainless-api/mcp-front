package integration

import (
	"net/http"
	"testing"
)

// TestAuthMatrix_ServiceAuthOnly exercises the per-credential matrix on a
// deployment configured with serviceAuths (Bearer + Basic) and NO global OAuth.
// Every 401 must carry WWW-Authenticate: Basic realm="mcp-front" (gate output
// when oauthEnabled=false). 200s must come from the MCP handler.
func TestAuthMatrix_ServiceAuthOnly(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-auth-matrix-service-only",
		nil, // no global OAuth
		map[string]any{
			"postgres": testPostgresServer(
				withBearerTokens("svc-bearer-1"),
				withBasicAuth("svc-user", "SVC_PASSWORD"),
			),
		},
	)
	startMCPFront(t, writeTestConfig(t, cfg),
		"SVC_PASSWORD=svcpass789",
	)
	waitForMCPFront(t)

	const basicChallenge = `Basic realm="mcp-front"`
	cases := []authMatrixCase{
		{
			name:       "row 4 — bearer matching serviceAuths.Tokens",
			authHeader: "Bearer svc-bearer-1",
			wantStatus: http.StatusOK,
		},
		{
			name:          "row 5 — bearer not matching anything",
			authHeader:    "Bearer not-a-known-token",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: basicChallenge,
		},
		{
			name:       "row 6 — basic matching serviceAuths user/pass",
			authHeader: basicHeader("svc-user", "svcpass789"),
			wantStatus: http.StatusOK,
		},
		{
			name:          "row 7 — basic with wrong password",
			authHeader:    basicHeader("svc-user", "wrongpass"),
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: basicChallenge,
		},
		{
			name:          "row 8 — basic with unknown user",
			authHeader:    basicHeader("nobody", "anypass"),
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: basicChallenge,
		},
		{
			name:          "row 9 — malformed basic (bad base64)",
			authHeader:    "Basic not_base64!!!",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: basicChallenge,
		},
		{
			name:          "row 10 — malformed basic (decoded payload has no colon)",
			authHeader:    "Basic c3Zjbm9jb2xvbg==", // base64("svcnocolon")
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: basicChallenge,
		},
		{
			name:          "row 11 — no Authorization header",
			authHeader:    "",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: basicChallenge,
		},
		{
			name:          "row 12 — empty Bearer (no token after scheme)",
			authHeader:    "Bearer ",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: basicChallenge,
		},
	}

	runAuthMatrix(t, "http://localhost:8080/postgres/sse", cases)
}
