package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleForwardAuth(t *testing.T) {
	tests := []struct {
		name    string
		addUser bool
		allow   bool
		want    int
	}{
		{"no authenticated user", false, true, http.StatusUnauthorized},
		{"not allowed", true, false, http.StatusForbidden},
		{"allowed", true, true, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorizer := authz.Authorizer{
				Rules: []authz.Rule{
					{
						Domain: "*.example.com",
						Users:  []string{"foo@example.com"},
					},
				},
			}

			h := withForwardAuthMiddleware()(
				handleForwardAuth(
					&authorizer,
					slog.New(slog.DiscardHandler),
				),
			)

			target := "https://www.example.com/?mode=\"a b\""
			if !tt.allow {
				target = "https://www.badexample.com"
			}

			req := forwardAuthRequest(target)
			if tt.addUser {
				req = session.SetAuthenticatedUser(req, provider.Identity{Email: "foo@example.com"})
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, tt.want, resp.Code)
		})
	}
}

func TestForwardAuthHandler_Headers(t *testing.T) {
	type wantedHeaders struct {
		name   string
		email  string
		groups string
	}
	tests := []struct {
		name     string
		groups   []string
		userInfo provider.Identity
		want     wantedHeaders
	}{
		{"no groups", nil, provider.Identity{Name: "foo", Email: "foo@example.com"}, wantedHeaders{"foo", "foo@example.com", ""}},
		{"groups", []string{"admin", "users"}, provider.Identity{Name: "foo", Email: "foo@example.com"}, wantedHeaders{"foo", "foo@example.com", "admin,users"}},
		{"no name", nil, provider.Identity{Email: "foo@example.com"}, wantedHeaders{"", "foo@example.com", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := withForwardAuthMiddleware()(
				handleForwardAuth(
					&fakeAuthorizer{allow: true, groups: tt.groups},
					slog.New(slog.DiscardHandler),
				),
			)

			req := forwardAuthRequest("/")
			req = session.SetAuthenticatedUser(req, tt.userInfo)
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, http.StatusOK, resp.Code)

			require.Equal(t, tt.want.name, resp.Header().Get(forwardedUserNameHeader))
			require.Equal(t, tt.want.email, resp.Header().Get(forwardedUserEmailHeader))
			require.Equal(t, tt.want.groups, resp.Header().Get(forwardedUserGroupsHeader))
		})
	}
}

func forwardAuthRequest(s string) *http.Request {
	u, _ := url.Parse(s)
	path := u.Path
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Uri", path)
	req.Header.Set("X-Forwarded-Proto", u.Scheme)
	req.Header.Set("X-Forwarded-Host", u.Host)
	req.Header.Set("X-Forwarded-Method", http.MethodGet)
	return req
}

func TestOriginalRequest(t *testing.T) {
	type want struct {
		method string
		path   string
	}
	tests := []struct {
		name    string
		headers map[string]string
		want    want
	}{
		{
			name:    "basic",
			headers: map[string]string{"X-Forwarded-Uri": "/", "X-Forwarded-Host": "example.com"},
			want:    want{http.MethodGet, "https://example.com/"},
		},
		{
			name:    "method",
			headers: map[string]string{"X-Forwarded-Method": http.MethodPost, "X-Forwarded-Uri": "/", "X-Forwarded-Host": "example.com"},
			want:    want{http.MethodPost, "https://example.com/"},
		},
		{
			name:    "encoded path",
			headers: map[string]string{"X-Forwarded-Uri": "/files/a%2Fb", "X-Forwarded-Host": "example.com"},
			want:    want{http.MethodGet, "https://example.com/files/a%2Fb"},
		},
		{
			name:    "arguments",
			headers: map[string]string{"X-Forwarded-Uri": "/?arg=true", "X-Forwarded-Host": "example.com"},
			want:    want{http.MethodGet, "https://example.com/?arg=true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			req, err := originalRequest(req)
			require.NoError(t, err)
			assert.Equal(t, tt.want.method, req.Method)
			assert.Equal(t, tt.want.path, req.URL.String())
		})
	}
}

func BenchmarkOriginalRequest(b *testing.B) {
	req := forwardAuthRequest("https://example.com")
	b.ReportAllocs()
	for b.Loop() {
		_, err := originalRequest(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ Authorizer = (*fakeAuthorizer)(nil)

type fakeAuthorizer struct {
	allow  bool
	groups []string
}

func (f *fakeAuthorizer) GroupsForUser(_ string) []string {
	return f.groups
}

func (f *fakeAuthorizer) Allow(_ *url.URL, _ string) bool {
	return f.allow
}
