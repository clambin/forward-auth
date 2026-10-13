package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/forwardauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleForwardAuth(t *testing.T) {
	validKey := []byte("valid-key")
	type generateTokenFunc func(tb testing.TB, h *forwardauth.Handler, req *http.Request) string
	// generateToken generates a token, signed by key, with a delta time added to the expiration time
	generateToken := func(key []byte, delta time.Duration) func(tb testing.TB, h *forwardauth.Handler, req *http.Request) string {
		return func(tb testing.TB, h *forwardauth.Handler, req *http.Request) string {
			tok, err := h.CreateSession(t.Context(), provider.Identity{Email: "foo@example.com"}, req)
			require.NoError(tb, err)
			tok.ExpiresAt.Time = tok.ExpiresAt.Add(delta)
			rawToken, err := tok.Sign(key)
			require.NoError(tb, err)
			return rawToken
		}
	}

	tests := []struct {
		name  string
		token generateTokenFunc
		allow bool
		want  int
	}{
		{
			name:  "valid session, allowed",
			token: generateToken(validKey, 0),
			allow: true,
			want:  http.StatusOK,
		},
		{
			name:  "valid expired jwt",
			token: generateToken(validKey, -time.Hour),
			allow: true,
			want:  http.StatusOK,
		},
		{
			name:  "invalid signature on jwt",
			token: generateToken([]byte("wrong-key"), 0),
			allow: true,
			want:  http.StatusSeeOther,
		},
		{
			name:  "missing token",
			allow: true,
			want:  http.StatusSeeOther,
		},
		{
			name:  "valid session, not allowed",
			token: generateToken(validKey, 0),
			allow: false,
			want:  http.StatusForbidden,
		},
		{
			name: "invalid cookie",
			token: func(tb testing.TB, h *forwardauth.Handler, req *http.Request) string {
				return "invalid"
			},
			allow: true,
			want:  http.StatusSeeOther,
		},
		{
			name: "no session",
			token: func(tb testing.TB, h *forwardauth.Handler, req *http.Request) string {
				tok, err := h.CreateSession(t.Context(), provider.Identity{Email: "foo@example.com"}, req)
				require.NoError(tb, err)
				rawToken, err := tok.Sign(validKey)
				require.NoError(tb, err)
				require.NoError(tb, h.DeleteSession(t.Context(), tok.Identity.Email, tok.SessionID))
				return rawToken
			},
			allow: true,
			want:  http.StatusSeeOther,
		},
		{
			name: "unrecognized refresh token",
			token: func(tb testing.TB, h *forwardauth.Handler, req *http.Request) string {
				tok, err := h.CreateSession(t.Context(), provider.Identity{Email: "foo@example.com"}, req)
				require.NoError(tb, err)
				tok.RefreshToken = forwardauth.RefreshToken{}
				rawToken, err := tok.Sign(validKey)
				require.NoError(tb, err)
				return rawToken
			},
			allow: true,
			want:  http.StatusSeeOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cookieName = "test"
			var fAuthn fakeAuthenticator
			fAuthz := fakeAuthorizer{allow: tt.allow}
			handler, _ := forwardauth.New(time.Hour, &fAuthz, configuration.StorageConfiguration{})

			h := handleForwardAuth(
				cookieName,
				validKey,
				".example.com",
				handler,
				&fAuthn,
				slog.New(slog.DiscardHandler),
			)

			req := forwardAuthRequest("https://example.com/?mode=true")
			if tt.token != nil {
				req.AddCookie(&http.Cookie{Name: cookieName, Value: tt.token(t, handler, req)})
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, tt.want, resp.Code)

			if resp.Code == http.StatusSeeOther {
				assert.Contains(t, resp.Header().Get("Location"), "https://oicd.example.com/_oauth?code=")
			}
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
			const cookieName = "test"
			handler, _ := forwardauth.New(5*time.Minute, &fakeAuthorizer{allow: true, groups: tt.groups}, configuration.StorageConfiguration{})

			h := handleForwardAuth(
				cookieName,
				[]byte("my-signing-key"),
				".example.com",
				handler,
				&fakeAuthenticator{
					states: make(map[string]string),
					codes:  make(map[string]struct{}),
				},

				slog.New(slog.DiscardHandler),
			)

			req := forwardAuthRequest("/")

			token, err := handler.CreateSession(t.Context(), tt.userInfo, req)
			require.NoError(t, err)
			rawToken, err := token.Sign([]byte("my-signing-key"))
			require.NoError(t, err)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: rawToken})

			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, http.StatusOK, resp.Code)

			require.Equal(t, tt.want.name, resp.Header().Get(forwardedUserNameHeader))
			require.Equal(t, tt.want.email, resp.Header().Get(forwardedUserEmailHeader))
			require.Equal(t, tt.want.groups, resp.Header().Get(forwardedUserGroupsHeader))
		})
	}
}

func BenchmarkForwardAuthHandler(b *testing.B) {
	// Current:
	// BenchmarkForwardAuthHandler-10    	  267277	      4484 ns/op	    5934 B/op	      69 allocs/op
	// Without reqID:
	// BenchmarkForwardAuthHandler-10    	  283459	      4219 ns/op	    5757 B/op	      66 allocs/op
	const cookieName = "test"
	var fAuthn fakeAuthenticator
	handler, _ := forwardauth.New(time.Hour, &fakeAuthorizer{allow: true}, configuration.StorageConfiguration{})
	s := New(
		configuration.ServerConfiguration{CookieName: cookieName, Key: "secret", Domain: ".example.com"},
		handler,
		&fAuthn,
		&fakeMetrics{},
		slog.New(slog.DiscardHandler),
	)

	req := forwardAuthRequest("/")
	tok, err := handler.CreateSession(b.Context(), provider.Identity{Email: "foo@example.com"}, req)
	require.NoError(b, err)
	rawToken, _ := tok.Sign([]byte("secret"))
	require.NoError(b, err)
	cookie := http.Cookie{Name: cookieName, Value: rawToken}
	req.AddCookie(&cookie)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		reqC := req.Clone(b.Context())
		resp := httptest.NewRecorder()
		s.ServeHTTP(resp, reqC)
		if resp.Code != http.StatusOK {
			b.Fatal("should be OK")
		}
	}
}

func TestHandleLogin(t *testing.T) {
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
			const cookieName = "test"
			handler, _ := forwardauth.New(time.Hour, nil, configuration.StorageConfiguration{})
			h := handleLogin(
				cookieName,
				[]byte("secret"),
				".example.com",
				handler,
				&fa,
				slog.New(slog.DiscardHandler),
			)

			req := httptest.NewRequest(http.MethodGet, "/api/auth/login?"+tt.args.Encode(), nil)
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, tt.want.code, resp.Code)

			if tt.want.code != http.StatusSeeOther {
				return
			}

			require.Equal(t, tt.want.location, resp.Header().Get("Location"))
			cookies := resp.Result().Cookies()
			require.Len(t, cookies, 1)
			require.Equal(t, cookieName, cookies[0].Name)
			assert.NotZero(t, cookies[0].Value)
		})
	}
}

func forwardAuthRequest(s string) *http.Request {
	u, _ := url.Parse(s)
	path := u.Path
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/forwardauth", nil)
	req.Header.Set("X-Forwarded-Uri", path)
	req.Header.Set("X-Forwarded-Proto", u.Scheme)
	req.Header.Set("X-Forwarded-Host", u.Host)
	req.Header.Set("X-Forwarded-Method", http.MethodGet)
	return req
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ Authenticator = (*fakeAuthenticator)(nil)

type fakeAuthenticator struct {
	states map[string]string
	codes  map[string]struct{}
	mu     sync.Mutex
}

func (f *fakeAuthenticator) InitiateLogin(_ context.Context, u string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states == nil {
		f.states = make(map[string]string)
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	state := hex.EncodeToString(b[:])
	f.states[state] = u

	vals := url.Values{
		"state": {state},
		"code":  {"1234"},
	}
	return "https://oicd.example.com/_oauth?" + vals.Encode(), nil
}

func (f *fakeAuthenticator) ConfirmLogin(_ context.Context, state, code string) (provider.Identity, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.codes[code]; !ok {
		return provider.Identity{}, "", errors.New("invalid code")
	}
	u, ok := f.states[state]
	if !ok {
		return provider.Identity{}, "", errors.New("invalid state")
	}
	return provider.Identity{Name: "foo", Email: "foo@example.com"}, u, nil
}

var _ forwardauth.Authorizer = (*fakeAuthorizer)(nil)

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

var _ Metrics = (*fakeMetrics)(nil)

type fakeMetrics struct{}

func (f fakeMetrics) InstrumentedHandler(_ string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}
