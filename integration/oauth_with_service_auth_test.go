package integration

import (
	"net/http"
	"testing"
)

// authMatrixBoth returns the row 1-12 cases for column (C) of the matrix:
// global OAuth AND serviceAuths configured. The expected behavior is identical
// for direct MCP server routes and aggregate routes — exercised by both
// TestAuthMatrix_Both_DirectRoute and TestAuthMatrix_Both_AggregateRoute below
// to guard the two call sites in internal/mcpfront.go that construct the
// per-route auth chain.
func authMatrixBoth(serviceName, validOAuthToken, otherAudienceToken string) []authMatrixCase {
	const issuer = "http://localhost:8080"
	challenge := rfc9728BearerHeader(issuer, serviceName)
	return []authMatrixCase{
		{
			name:       "row 1 — valid OAuth Bearer JWT",
			authHeader: "Bearer " + validOAuthToken,
			wantStatus: http.StatusOK,
		},
		{
			name:          "row 2 — invalid OAuth Bearer JWT (tampered)",
			authHeader:    "Bearer " + validOAuthToken + "tamper",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
		{
			name:          "row 3 — wrong-audience OAuth Bearer JWT",
			authHeader:    "Bearer " + otherAudienceToken,
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
		{
			name:       "row 4 — bearer matching serviceAuths.Tokens",
			authHeader: "Bearer svc-bearer-1",
			wantStatus: http.StatusOK,
		},
		{
			name:          "row 5 — bearer not matching anything",
			authHeader:    "Bearer not-svc-not-jwt",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
		{
			name:       "row 6 — basic matching serviceAuths user/pass",
			authHeader: basicHeader("svc-user", "svcpass789"),
			wantStatus: http.StatusOK,
		},
		{
			name:          "row 7 — basic with wrong password (gate prefers OAuth challenge)",
			authHeader:    basicHeader("svc-user", "wrongpass"),
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
		{
			name:          "row 8 — basic with unknown user",
			authHeader:    basicHeader("nobody", "anypass"),
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
		{
			name:          "row 9 — malformed basic (bad base64)",
			authHeader:    "Basic not_base64!!!",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
		{
			name:          "row 10 — malformed basic (decoded payload has no colon)",
			authHeader:    "Basic " + "c3Zjbm9jb2xvbg==",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
		{
			name:          "row 11 — no Authorization header",
			authHeader:    "",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
		{
			name:          "row 12 — empty Bearer (no token after scheme)",
			authHeader:    "Bearer ",
			wantStatus:    http.StatusUnauthorized,
			wantWWWAuthEq: challenge,
		},
	}
}

// TestAuthMatrix_Both_DirectRoute exercises the matrix on a direct MCP server
// route (postgres) configured with both global OAuth and per-server serviceAuths.
// This is the case the original PR #58 was trying to fix; the fix here closes
// both directions of the bug (OAuth-eats-Basic AND ServiceAuth-eats-OAuth-JWT).
func TestAuthMatrix_Both_DirectRoute(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-auth-matrix-both-direct",
		testOAuthConfigFromEnv(),
		map[string]any{
			"postgres": testPostgresServer(
				withBearerTokens("svc-bearer-1"),
				withBasicAuth("svc-user", "SVC_PASSWORD"),
			),
			"other": testPostgresServer(),
		},
	)
	startMCPFront(t, writeTestConfig(t, cfg),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
		"SVC_PASSWORD=svcpass789",
	)
	waitForMCPFront(t)

	validOAuthToken := getOAuthAccessToken(t, "http://localhost:8080/postgres")
	otherToken := getOAuthAccessToken(t, "http://localhost:8080/other")

	runAuthMatrix(t,
		"http://localhost:8080/postgres/sse",
		authMatrixBoth("postgres", validOAuthToken, otherToken),
	)
}

// TestAuthMatrix_Both_AggregateRoute exercises the same matrix on an aggregate
// MCP server route. mcpfront.go has two structurally identical call sites that
// construct the per-route auth chain (one for direct servers, one for
// aggregates); this test guards the second site.
func TestAuthMatrix_Both_AggregateRoute(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-auth-matrix-both-aggregate",
		testOAuthConfigFromEnv(),
		map[string]any{
			"postgres": testPostgresServer(),
			"other":    testPostgresServer(),
			"mcp": map[string]any{
				"type":          "aggregate",
				"transportType": "sse",
				"servers":       []string{"postgres"},
				"discovery": map[string]any{
					"timeout":  "10s",
					"cacheTtl": "60s",
				},
				"serviceAuths": []map[string]any{
					{"type": "bearer", "name": "svc", "tokens": []string{"svc-bearer-1"}},
					{"type": "basic", "username": "svc-user", "password": map[string]string{"$env": "SVC_PASSWORD"}},
				},
			},
		},
	)
	startMCPFront(t, writeTestConfig(t, cfg),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
		"SVC_PASSWORD=svcpass789",
	)
	waitForMCPFront(t)

	validOAuthToken := getOAuthAccessToken(t, "http://localhost:8080/mcp")
	otherToken := getOAuthAccessToken(t, "http://localhost:8080/other")

	runAuthMatrix(t,
		"http://localhost:8080/mcp/sse",
		authMatrixBoth("mcp", validOAuthToken, otherToken),
	)
}
