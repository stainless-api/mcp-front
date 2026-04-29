package integration

import (
	"net/http"
	"testing"
)

// TestAuthMatrix_OAuthOnly exercises the per-credential matrix on a deployment
// configured with global OAuth and NO serviceAuths. Every 401 must carry an
// RFC 9728 Bearer challenge with the per-service resource_metadata URI.
//
// Two MCP server routes are configured (postgres, other) so a token minted for
// one can be replayed against the other to exercise the wrong-audience case.
func TestAuthMatrix_OAuthOnly(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-auth-matrix-oauth-only",
		testOAuthConfigFromEnv(),
		map[string]any{
			"postgres": testPostgresServer(),
			"other":    testPostgresServer(),
		},
	)
	startMCPFront(t, writeTestConfig(t, cfg),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
	)
	waitForMCPFront(t)

	const issuer = "http://localhost:8080"
	postgresChallenge := rfc9728BearerHeader(issuer, "postgres")

	validPostgresToken := getOAuthAccessToken(t, "http://localhost:8080/postgres")
	otherToken := getOAuthAccessToken(t, "http://localhost:8080/other")

	cases := []authMatrixCase{
		{
			name:       "row 1 — valid OAuth Bearer JWT",
			authHeader: "Bearer " + validPostgresToken,
			wantStatus: http.StatusOK,
		},
		{
			name:          "row 2 — invalid OAuth Bearer JWT (tampered signature)",
			authHeader:    "Bearer " + validPostgresToken + "tamper",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: postgresChallenge,
		},
		{
			name:          "row 3 — wrong-audience OAuth Bearer JWT",
			authHeader:    "Bearer " + otherToken, // minted for /other, sent to /postgres
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: postgresChallenge,
		},
		{
			name:          "row 4 — bearer not matching (no serviceAuths configured)",
			authHeader:    "Bearer arbitrary-non-jwt-token",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: postgresChallenge,
		},
		{
			name:          "row 6/7 — Basic header on an OAuth-only deployment",
			authHeader:    basicHeader("svc-user", "svcpass789"),
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: postgresChallenge,
		},
		{
			name:          "row 9 — malformed Basic on an OAuth-only deployment",
			authHeader:    "Basic not_base64!!!",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: postgresChallenge,
		},
		{
			name:          "row 11 — no Authorization header",
			authHeader:    "",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: postgresChallenge,
		},
		{
			name:          "row 12 — empty Bearer (no token after scheme)",
			authHeader:    "Bearer ",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: postgresChallenge,
		},
	}

	runAuthMatrix(t, "http://localhost:8080/postgres/sse", cases)
}
