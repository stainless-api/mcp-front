package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stainless-api/mcp-front/internal/oauth"
	"github.com/stainless-api/mcp-front/internal/servicecontext"
	"github.com/stretchr/testify/assert"
)

func TestRequireAuthMiddleware(t *testing.T) {
	const issuer = "https://mcp.example.com"

	type setup struct {
		oauthEnabled  bool
		issuer        string
		path          string
		injectOAuth   *string // nil = no OAuth context; non-nil = set context to value (even empty)
		injectService bool
	}
	stringp := func(s string) *string { return &s }
	type want struct {
		status                int
		handlerCalled         bool
		wwwAuthHeaderContains string // empty means must be empty
		wwwAuthHeaderEqual    string // optional exact match
	}

	cases := []struct {
		name  string
		setup setup
		want  want
	}{
		{
			name:  "OAuth user in context: pass-through",
			setup: setup{oauthEnabled: true, issuer: issuer, path: "/postgres/sse", injectOAuth: stringp("alice@example.com")},
			want:  want{status: http.StatusOK, handlerCalled: true},
		},
		{
			name:  "OAuth context set with empty email (validated but no email): pass-through",
			setup: setup{oauthEnabled: true, issuer: issuer, path: "/postgres/sse", injectOAuth: stringp("")},
			want:  want{status: http.StatusOK, handlerCalled: true},
		},
		{
			name:  "service auth in context: pass-through",
			setup: setup{oauthEnabled: true, issuer: issuer, path: "/postgres/sse", injectService: true},
			want:  want{status: http.StatusOK, handlerCalled: true},
		},
		{
			name:  "service auth in context, OAuth disabled: pass-through",
			setup: setup{oauthEnabled: false, issuer: "", path: "/postgres/sse", injectService: true},
			want:  want{status: http.StatusOK, handlerCalled: true},
		},
		{
			name:  "no identity, OAuth enabled, path resolves to service: RFC 9728 Bearer with resource_metadata",
			setup: setup{oauthEnabled: true, issuer: issuer, path: "/postgres/sse"},
			want: want{
				status:                http.StatusUnauthorized,
				wwwAuthHeaderEqual:    `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/postgres"`,
				wwwAuthHeaderContains: "Bearer",
			},
		},
		{
			name:  "no identity, OAuth enabled, root path: bare 401 with no challenge URI",
			setup: setup{oauthEnabled: true, issuer: issuer, path: "/"},
			want:  want{status: http.StatusUnauthorized}, // WriteUnauthorizedRFC9728 emits no header when URI empty
		},
		{
			name:  "no identity, OAuth disabled (ServiceAuth-only deployment): Basic realm",
			setup: setup{oauthEnabled: false, issuer: "", path: "/postgres/sse"},
			want: want{
				status:             http.StatusUnauthorized,
				wwwAuthHeaderEqual: `Basic realm="mcp-front"`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var handlerCalled bool
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			ctx := context.Background()
			if tc.setup.injectOAuth != nil {
				ctx = context.WithValue(ctx, oauth.GetUserContextKey(), *tc.setup.injectOAuth)
			}
			if tc.setup.injectService {
				ctx = servicecontext.WithAuthInfo(ctx, "svc", "tok")
			}

			req := httptest.NewRequest("GET", tc.setup.path, nil).WithContext(ctx)
			rr := httptest.NewRecorder()
			NewRequireAuthMiddleware(tc.setup.oauthEnabled, tc.setup.issuer)(handler).ServeHTTP(rr, req)

			assert.Equal(t, tc.want.status, rr.Code)
			assert.Equal(t, tc.want.handlerCalled, handlerCalled)

			gotHeader := rr.Header().Get("WWW-Authenticate")
			if tc.want.wwwAuthHeaderEqual != "" {
				assert.Equal(t, tc.want.wwwAuthHeaderEqual, gotHeader)
			} else if tc.want.wwwAuthHeaderContains != "" {
				assert.Contains(t, gotHeader, tc.want.wwwAuthHeaderContains)
			} else {
				assert.Empty(t, gotHeader)
			}
		})
	}
}
