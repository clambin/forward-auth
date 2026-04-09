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
	"github.com/clambin/forward-auth/internal/sessions"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForwardAuthHandler(t *testing.T) {
	tests := []struct {
		name        string
		withSession bool
		allow       bool
		wantCode    int
	}{
		{"no session", false, true, http.StatusSeeOther},
		{"invalid session", false, true, http.StatusSeeOther},
		{"valid session, not allowed", true, false, http.StatusForbidden},
		{"valid session, allowed", true, true, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cookieName = "test"
			var fAuthn fakeAuthenticator
			fAuthz := fakeAuthorizer{allow: tt.allow}
			mgr, _ := sessions.New(5*time.Minute, configuration.StorageConfiguration{})

			s := New(
				configuration.ServerConfiguration{CookieName: cookieName, Domain: "example.com"},
				mgr,
				&fAuthn,
				&fAuthz,
				&fakeRedisClient{},
				&fakeMetrics{},
				slog.New(slog.DiscardHandler),
			)

			req := forwardAuthRequest("/")
			if tt.withSession {
				sessionID, err := mgr.Add(t.Context(), provider.UserInfo{Email: "foo@example.com"}, "")
				require.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: cookieName, Value: sessionID})
			}
			resp := httptest.NewRecorder()
			s.ServeHTTP(resp, req)
			assert.Equal(t, tt.wantCode, resp.Code)
		})
	}
}

func forwardAuthRequest(s string) *http.Request {
	u, _ := url.Parse(s)
	req := httptest.NewRequest(http.MethodGet, "/api/auth/forwardauth", nil)
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
			const cookieName = "test"
			mgr, _ := sessions.New(5*time.Minute, configuration.StorageConfiguration{})
			h := loginHandler(cookieName, ".example.com", &fa, mgr, slog.New(slog.DiscardHandler))

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

func (f *fakeAuthenticator) ConfirmLogin(_ context.Context, state, code string) (provider.UserInfo, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.codes[code]; !ok {
		return provider.UserInfo{}, "", errors.New("invalid code")
	}
	u, ok := f.states[state]
	if !ok {
		return provider.UserInfo{}, "", errors.New("invalid state")
	}
	return provider.UserInfo{Email: "foo@example.com"}, u, nil
}

var _ Authorizer = (*fakeAuthorizer)(nil)

type fakeAuthorizer struct {
	allow bool
}

func (f *fakeAuthorizer) Allow(_ *url.URL, _ string) bool {
	return f.allow
}

var _ Metrics = (*fakeMetrics)(nil)

type fakeMetrics struct{}

func (f fakeMetrics) InstrumentedHandler(_ string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

var _ RedisClient = fakeRedisClient{}

type fakeRedisClient struct{ err error }

func (f fakeRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetErr(f.err)
	return cmd
}
