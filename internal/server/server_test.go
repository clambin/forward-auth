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
	"sync/atomic"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/auth"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	var fa fakeForwardAuth
	var p fakePing
	s := New(DefaultConfiguration, &fa, &p, GetMetrics(), slog.New(slog.DiscardHandler))

	// No session: redirect to oidc
	resp := httptest.NewRecorder()
	s.ServeHTTP(resp, forwardAuthRequest("https://www.example.com"))
	require.Equal(t, http.StatusSeeOther, resp.Code)
	loginURL := resp.Header().Get("Location")
	require.Contains(t, loginURL, "/_oauth?")

	parsedLoginURL, err := url.Parse(loginURL)
	require.NoError(t, err)
	state := parsedLoginURL.Query().Get("state")
	require.NotZero(t, state)
	code := parsedLoginURL.Query().Get("code")
	require.NotZero(t, code)

	// emulate the oidc callback
	v := url.Values{"code": {code}, "state": {state}}
	req, _ := http.NewRequest(http.MethodGet, "/_oauth?"+v.Encode(), nil)
	resp = httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	require.Equal(t, http.StatusSeeOther, resp.Code)

	// get tne cookie from the response
	cookies := resp.Result().Cookies()
	require.Len(t, cookies, 1)

	// request with a valid session cookie should succeed
	req = forwardAuthRequest("https://www.example.com")
	req.AddCookie(cookies[0])
	resp = httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// logout
	req = forwardAuthRequest("https://www.example.com/_oauth/logout")
	req.AddCookie(cookies[0])
	resp = httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// cookie is now invalid: attempting to use it will redirect to oidc
	req = forwardAuthRequest("https://www.example.com")
	req.AddCookie(cookies[0])
	resp = httptest.NewRecorder()
	s.ServeHTTP(resp, req)
	require.Equal(t, http.StatusSeeOther, resp.Code)
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

var _ ForwardAuth = (*fakeForwardAuth)(nil)

type fakeForwardAuth struct {
	sessions map[string]string
	states   map[string]string
	mu       sync.Mutex
}

func (f *fakeForwardAuth) ValidateSession(_ context.Context, sessionID string, _ *url.URL) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if user, ok := f.sessions[sessionID]; ok {
		return user, nil
	}
	return "", auth.ErrNoSession
}

func (f *fakeForwardAuth) DeleteSession(_ context.Context, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, sessionID)
	return nil
}

func (f *fakeForwardAuth) InitiateLogin(_ context.Context, u string) (string, error) {
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

func (f *fakeForwardAuth) ConfirmLogin(_ context.Context, state string, code string) (string, string, string, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if code != "1234" {
		return "", "", "", 0, errors.New("invalid code")
	}
	if f.states[state] == "" {
		return "", "", "", 0, errors.New("invalid state")
	}
	if f.sessions == nil {
		f.sessions = make(map[string]string)
	}
	f.sessions["12345678"] = "foo@example.com"
	return "foo@example.com", "12345678", f.states[state], time.Hour, nil
}

var _ RedisClient = (*fakePing)(nil)

type fakePing struct {
	pings atomic.Int64
}

func (f *fakePing) Ping(ctx context.Context) *redis.StatusCmd {
	f.pings.Add(1)
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetErr(nil)
	return cmd
}
