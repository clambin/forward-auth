package session

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	"github.com/clambin/forward-auth/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessions(t *testing.T) {
	endpoint := testutils.RedisTestContainer(t)

	tests := []struct {
		name string
		ttl  time.Duration
		cfg  configuration.StorageConfiguration
	}{
		{"redis", 5 * time.Minute, configuration.StorageConfiguration{Type: "redis", Redis: configuration.StorageRedisConfiguration{Addr: endpoint}}},
		{"memory", 5 * time.Minute, configuration.StorageConfiguration{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", "test")

			sessions, err := New(
				tt.ttl,
				configuration.ServerConfiguration{},
				tt.cfg,
				nil,
				slog.New(slog.DiscardHandler),
			)
			require.NoError(t, err)

			// create a session
			identity := provider.Identity{Email: "foo@example.com", Name: "foo", Subject: "1234"}
			token, err := sessions.CreateSession(ctx, identity, req)
			require.NoError(t, err)

			assert.Equal(t, identity, token.Identity)
			assert.False(t, token.Expired())

			// expire the token
			token.ExpiresAt.Time = time.Now().Add(-1 * time.Minute)
			assert.True(t, token.Expired())

			// mgr should issue a new token
			oldToken := token
			token, err = sessions.Validate(ctx, token, req)
			require.NoError(t, err)
			assert.Equal(t, "foo@example.com", token.Identity.Email)
			assert.False(t, token.Expired())
			assert.NotEqual(t, oldToken.RefreshToken, token.RefreshToken)

			// the previous refresh token is still accepted (e.g. concurrent requests) and yields the same refresh token
			concurrentToken, err := sessions.Validate(ctx, oldToken, req)
			require.NoError(t, err)
			assert.False(t, concurrentToken.Expired())
			assert.Equal(t, token.RefreshToken, concurrentToken.RefreshToken)

			// renewing the current refresh token again rotates it
			token.ExpiresAt.Time = time.Now().Add(-1 * time.Minute)
			previousToken := token
			token, err = sessions.Validate(ctx, token, req)
			require.NoError(t, err)
			assert.NotEqual(t, previousToken.RefreshToken, token.RefreshToken)

			// the previous refresh token is still accepted, but the one before that is not
			_, err = sessions.Validate(ctx, previousToken, req)
			require.NoError(t, err)
			_, err = sessions.Validate(ctx, oldToken, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)

			// once the grace period has passed, the previous refresh token is no longer accepted
			s, err := sessions.get(ctx, token.Identity.Email, token.SessionID)
			require.NoError(t, err)
			s.RotatedAt = time.Now().Add(-refreshTokenGracePeriod - time.Second)
			require.NoError(t, sessions.put(ctx, token.Identity.Email, token.SessionID, s))
			_, err = sessions.Validate(ctx, previousToken, req)
			require.ErrorIs(t, err, ErrPreviousRefreshTokenExpired)
			// the current refresh token is still accepted
			token, err = sessions.Validate(ctx, token, req)
			require.NoError(t, err)

			// only 1 session should exist
			found, err := sessions.Len(ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, found)

			// list the sessions
			activeSessions, err := sessions.List(ctx, "foo@example.com")
			require.NoError(t, err)
			require.Len(t, activeSessions, 1)
			// token is linked to the right session
			assert.Equal(t, token.SessionID, activeSessions[0].ID)
			// token is for the right user
			assert.Equal(t, "foo@example.com", activeSessions[0].Identity.Email)
			// session refresh token hash matches the token's refresh token
			assert.Equal(t, token.RefreshToken.hash(), activeSessions[0].RefreshTokenHash)
			// session captures the right user agent
			assert.Equal(t, "test", activeSessions[0].UserAgent)
			// timestamps are filled in
			assert.NotZero(t, activeSessions[0].IssuedAt)
			assert.NotZero(t, activeSessions[0].RotatedAt)

			// invalidate the token
			token.RefreshToken = generateRefreshToken()
			_, err = sessions.Validate(ctx, token, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)

			// delete the session
			err = sessions.DeleteSession(ctx, token.Identity.Email, token.SessionID)
			require.NoError(t, err)
			count, _ := sessions.Len(t.Context())
			assert.Zero(t, count)

			// delete a non-existent session returns an error
			err = sessions.DeleteSession(ctx, token.Identity.Email, token.SessionID)
			require.ErrorIs(t, err, ErrSessionNotFound)
		})
	}
}

// TestSessions_InvalidStorage verifies that the session store returns an error when the storage type is invalid.
func TestSessions_InvalidStorage(t *testing.T) {
	_, err := New(
		time.Hour,
		configuration.ServerConfiguration{},
		configuration.StorageConfiguration{Type: "invalid"},
		&fakeAuthenticator{},
		slog.New(slog.DiscardHandler),
	)
	require.Error(t, err)
}

// TestSessions_Decode verifies that the session format doesn't change in the session store.
func TestSessions_Decode(t *testing.T) {
	var secret [32]byte
	session := Session{
		IssuedAt:                 time.Date(2026, time.October, 13, 0, 0, 0, 0, time.UTC),
		RotatedAt:                time.Date(2026, time.October, 13, 0, 15, 0, 0, time.UTC),
		Identity:                 provider.Identity{Email: "foo@example.com"},
		ID:                       "my-fake-id",
		UserAgent:                "my-user-agent",
		RefreshSecret:            secret[:],
		RefreshTokenHash:         refreshTokenHash{},
		PreviousRefreshTokenHash: refreshTokenHash{},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(&session))
	want := `{
  "issuedAt": "2026-10-13T00:00:00Z",
  "rotatedAt": "2026-10-13T00:15:00Z",
  "identity": {
    "sub": "",
    "email": "foo@example.com",
    "name": ""
  },
  "id": "my-fake-id",
  "userAgent": "my-user-agent",
  "refreshSecret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "refreshTokenHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "previousRefreshTokenHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
`
	require.Equal(t, want, buf.String())
}

func TestSessions_LoginHandler(t *testing.T) {
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
			args: url.Values{"code": []string{"1234"}},
			want: want{code: http.StatusBadRequest},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.ServerConfiguration{
				CookieName: "test",
				Domain:     ".example.com",
				Key:        "secret",
				HealthPath: "/healthz",
			}
			h, _ := New(
				time.Hour,
				cfg,
				configuration.StorageConfiguration{},
				&fakeAuthenticator{
					states: map[string]string{"4321": "/"},
					codes:  map[string]struct{}{"1234": {}},
				},
				slog.New(slog.DiscardHandler),
			)
			handler := h.LoginHandler(slog.New(slog.DiscardHandler))

			req := httptest.NewRequest(http.MethodGet, "/api/auth/login?"+tt.args.Encode(), nil)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			require.Equal(t, tt.want.code, resp.Code)

			if tt.want.code != http.StatusSeeOther {
				return
			}

			require.Equal(t, tt.want.location, resp.Header().Get("Location"))
			cookies := resp.Result().Cookies()
			require.Len(t, cookies, 1)
			require.Equal(t, cfg.CookieName, cookies[0].Name)
			assert.NotZero(t, cookies[0].Value)
		})
	}
}

func TestSessions_Authenticator(t *testing.T) {
	const validKey = "valid-key"

	tests := []struct {
		name     string
		token    generateTokenFunc
		redirect bool
		method   string
		header   http.Header
		want     int
	}{
		{
			name:  "valid session, allowed",
			token: generateTestToken([]byte(validKey), 0),
			want:  http.StatusOK,
		},
		{
			name: "missing token, no redirect",
			want: http.StatusUnauthorized,
		},
		{
			name:  "expired JWT with valid session",
			token: generateTestToken([]byte(validKey), -time.Hour),
			want:  http.StatusOK,
		},
		{
			name:     "unauthenticated, navigation",
			redirect: true,
			header:   http.Header{"Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"}},
			want:     http.StatusSeeOther,
		},
		{
			name:     "unauthenticated, api",
			redirect: true,
			header:   http.Header{"Sec-Fetch-Mode": {"cors"}, "Sec-Fetch-Dest": {"empty"}},
			want:     http.StatusUnauthorized,
		},
		{
			name:     "unauthenticated GET, no Sec-Fetch headers",
			redirect: true,
			want:     http.StatusSeeOther,
		},
		{
			name:     "unauthenticated POST, no Sec-Fetch headers",
			redirect: true,
			method:   http.MethodPost,
			want:     http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.ServerConfiguration{
				CookieName: "test",
				Key:        validKey,
				Domain:     ".example.com",
				HealthPath: "/healthz",
			}
			h, _ := New(
				time.Hour,
				cfg,
				configuration.StorageConfiguration{},
				&fakeAuthenticator{},
				slog.New(slog.DiscardHandler),
			)

			s := h.Authenticator(tt.redirect)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// if the middleware accepts the token, it should set the authenticated user
				id, ok := AuthenticatedUser(r)
				require.True(t, ok)
				require.Equal(t, "foo@example.com", id.Email)
			}))

			req, _ := http.NewRequest(cmp.Or(tt.method, http.MethodGet), "/", nil)
			if tt.token != nil {
				req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: tt.token(t, h, req)})
			}
			for k, vs := range tt.header {
				for _, v := range vs {
					req.Header.Add(k, v)
				}
			}
			resp := httptest.NewRecorder()
			s.ServeHTTP(resp, req)
			assert.Equal(t, tt.want, resp.Code)

			if resp.Code == http.StatusSeeOther {
				assert.Contains(t, resp.Header().Get("Location"), "https://oicd.example.com/_oauth?code=")
			}
		})
	}
}

func BenchmarkSessions_Authenticator(b *testing.B) {
	// Current:
	// BenchmarkSessions_Authenticator-10    	  306352	      3588 ns/op	    4684 B/op	      55 allocs/op
	const cookieName = "test"
	h, _ := New(
		time.Hour,
		configuration.ServerConfiguration{CookieName: cookieName, Key: "secret", Domain: ".example.com", HealthPath: "/healthz"},
		configuration.StorageConfiguration{},
		&fakeAuthenticator{},
		slog.New(slog.DiscardHandler),
	)
	handler := h.Authenticator(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := AuthenticatedUser(r); !ok {
			b.Fatal("should be authenticated")
		}
	}))

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: generateTestToken([]byte("secret"), time.Hour)(b, h, &http.Request{})})

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		reqC := req.Clone(b.Context())
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, reqC)
		if resp.Code != http.StatusOK {
			b.Fatal("should be OK")
		}
	}
}

func TestSessions_authenticateRequest(t *testing.T) {
	const (
		validKey   = "secret"
		cookieName = "my-cookie"
	)
	tests := []struct {
		name      string
		token     generateTokenFunc
		err       require.ErrorAssertionFunc
		wantToken bool
	}{
		{"no cookie", nil, require.Error, false},
		{"valid session", generateTestToken([]byte(validKey), 0), require.NoError, false},
		{"expired JWT with valid session", generateTestToken([]byte(validKey), -time.Hour), require.NoError, true},
		{"invalid signature on JWT", generateTestToken([]byte("invalid-key"), 0), require.Error, false},
		{"invalid cookie", func(testing.TB, Sessions, *http.Request) string { return "invalid" }, require.Error, false},
		{
			name: "no session",
			token: func(tb testing.TB, h Sessions, req *http.Request) string {
				tok, err := h.CreateSession(t.Context(), provider.Identity{Email: "foo@example.com"}, req)
				require.NoError(tb, err)
				rawToken, err := tok.Sign([]byte(validKey))
				require.NoError(tb, err)
				require.NoError(tb, h.DeleteSession(t.Context(), tok.Identity.Email, tok.SessionID))
				return rawToken
			},
			err:       require.Error,
			wantToken: false,
		},
		{
			name: "unrecognized refresh token",
			token: func(tb testing.TB, h Sessions, req *http.Request) string {
				tok, err := h.CreateSession(t.Context(), provider.Identity{Email: "foo@example.com"}, req)
				require.NoError(tb, err)
				tok.RefreshToken = RefreshToken{}
				rawToken, err := tok.Sign([]byte(validKey))
				require.NoError(tb, err)
				return rawToken
			},
			err:       require.Error,
			wantToken: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.ServerConfiguration{
				CookieName: cookieName,
				Key:        validKey,
				Domain:     ".example.com",
			}
			s, _ := New(
				time.Hour,
				cfg,
				configuration.StorageConfiguration{},
				&fakeAuthenticator{},
				slog.New(slog.DiscardHandler),
			)

			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.token != nil {
				token := tt.token(t, s, req)
				req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
			}
			identity, updatedToken, err := s.authenticateRequest(req)
			tt.err(t, err)
			if err == nil {
				assert.Equal(t, "foo@example.com", identity.Email)
			}
			if tt.wantToken {
				assert.NotEmpty(t, updatedToken)
			}
		})
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// fakes

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

type generateTokenFunc func(tb testing.TB, h Sessions, req *http.Request) string

var _ generateTokenFunc = generateTestToken([]byte{}, 0)

// generateToken returns a test function that generates a token, signed by a key,
// with a delta time added to the expiration time
func generateTestToken(key []byte, delta time.Duration) func(tb testing.TB, h Sessions, req *http.Request) string {
	return func(tb testing.TB, h Sessions, req *http.Request) string {
		tok, err := h.CreateSession(tb.Context(), provider.Identity{Email: "foo@example.com"}, req)
		require.NoError(tb, err)
		tok.ExpiresAt.Time = tok.ExpiresAt.Add(delta)
		rawToken, err := tok.Sign(key)
		require.NoError(tb, err)
		return rawToken
	}
}

func Test_shouldRedirect(t *testing.T) {
	type args struct {
		method string
		mode   string
		dest   string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"navigate", args{http.MethodGet, "navigate", "document"}, true},
		{"non-GET navigate", args{http.MethodPost, "navigate", "document"}, true},
		{"API call", args{http.MethodPost, "cors", "empty"}, false},
		{"API call", args{http.MethodGet, "cors", "empty"}, false},
		{"websocket", args{http.MethodGet, "websocket", "empty"}, false},
		{"partial fetch data", args{http.MethodGet, "navigate", "empty"}, false},
		{"no headers GET", args{http.MethodGet, "", ""}, true},
		{"no headers non-GET", args{http.MethodPost, "", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.args.method, "/", nil)
			if tt.args.mode != "" {
				req.Header.Set("Sec-Fetch-Mode", tt.args.mode)
			}
			if tt.args.dest != "" {
				req.Header.Set("Sec-Fetch-Dest", tt.args.dest)
			}

			assert.Equal(t, tt.want, shouldRedirect(req))
		})
	}
}
