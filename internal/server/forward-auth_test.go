package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForwardAuthHandler(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		sessionID string
		sessions  map[string]authn.Session
		allow     bool
		wantCode  int
	}{
		{"no session", "/", "", nil, true, http.StatusSeeOther},
		{"invalid session", "/", "123", nil, true, http.StatusSeeOther},
		{"valid session, not allowed", "/", "123", map[string]authn.Session{"123": {}}, false, http.StatusForbidden},
		{"valid session, allowed", "/", "123", map[string]authn.Session{"123": {}}, true, http.StatusOK},
		{"logout, no session", "/_oauth/logout", "", nil, true, http.StatusUnauthorized},
		{"logout, valid session", "/_oauth/logout", "123", map[string]authn.Session{"123": {}}, true, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cookieName = "test"
			fa := fakeAuthenticator{sessions: tt.sessions}
			h := forwardAuthMiddleware()(
				withSessionValidator(cookieName, &fa)(
					ForwardAuthHandler(cookieName, ".example.com", &fa, &fakeAuthorizer{allow: tt.allow}, slog.New(slog.DiscardHandler)),
				),
			)
			req := forwardAuthRequest(tt.target)
			if tt.sessionID != "" {
				req.AddCookie(&http.Cookie{Name: "test", Value: tt.sessionID})
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, tt.wantCode, resp.Code)

		})
	}
}

func forwardAuthRequest(s string) *http.Request {
	u, _ := url.Parse(s)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Uri", u.Path)
	req.Header.Set("X-Forwarded-Proto", u.Scheme)
	req.Header.Set("X-Forwarded-Host", u.Host)
	req.Header.Set("X-Forwarded-Method", http.MethodGet)
	return req
}

func TestLoginHandler(t *testing.T) {
	type want struct {
		code     int
		location string
	}
	tests := []struct {
		name string
		args url.Values
		want want
	}{
		{
			name: "valid",
			args: url.Values{"code": []string{"1234"}, "state": []string{"4321"}},
			want: want{code: http.StatusSeeOther, location: "/"},
		},
		{
			name: "invalid",
			args: url.Values{"code": []string{"5678"}, "state": []string{"4321"}},
			want: want{code: http.StatusUnauthorized},
		},
		{
			name: "missing code",
			args: url.Values{"state": []string{"4321"}},
			want: want{code: http.StatusBadRequest},
		},
		{
			name: "missing state",
			args: url.Values{"state": []string{"4321"}},
			want: want{code: http.StatusBadRequest},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fa := fakeAuthenticator{
				states: map[string]string{"4321": "/"},
				codes:  map[string]struct{}{"1234": {}},
			}
			h := LoginHandler("cookie", ".example.com", &fa, slog.New(slog.DiscardHandler))

			req := httptest.NewRequest(http.MethodGet, "/login?"+tt.args.Encode(), nil)
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, tt.want.code, resp.Code)

			if tt.want.code != http.StatusSeeOther {
				return
			}

			require.Equal(t, tt.want.location, resp.Header().Get("Location"))
			cookies := resp.Result().Cookies()
			require.Len(t, cookies, 1)
			require.Equal(t, "cookie", cookies[0].Name)
			assert.Equal(t, "sessionID", cookies[0].Value)
		})
	}
}
