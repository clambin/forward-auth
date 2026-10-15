package server

import (
	"cmp"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/forwardauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListSessions(t *testing.T) {
	const username = "test@example.com"

	cfg := configuration.ServerConfiguration{
		CookieName: "forward-auth-session",
		Key:        "secret",
	}

	handler, err := forwardauth.New(time.Hour, &fakeAuthorizer{allow: true}, configuration.StorageConfiguration{})
	require.NoError(t, err)
	h := withForwardAuthToken(cfg, handler, &fakeAuthenticator{}, slog.New(slog.DiscardHandler))(
		routeSessions(handler, slog.New(slog.DiscardHandler)),
	)

	req, _ := createRequest(t, handler, username, cfg.CookieName, cfg.Key, http.MethodGet, "/list")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var sessions []listSessionsResponseItem
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sessions))
	require.Len(t, sessions, 1)
	assert.Equal(t, username, sessions[0].Identity.Email)
	assert.NotZero(t, sessions[0].SessionID)
}

func TestHandleDeleteSession(t *testing.T) {
	const username = "test@example.com"
	const invalidUsername = "invalid@example.com"
	cfg := configuration.ServerConfiguration{
		CookieName: "forward-auth-session",
		Key:        "secret",
	}

	tests := []struct {
		name     string
		path     string
		username string
		want     int
	}{
		{"missing session id", "/session/", username, http.StatusNotFound},
		{"wrong session id", "/session/invalid", username, http.StatusNotFound},
		{"wrong user in header", "", invalidUsername, http.StatusNotFound},
		{"valid", "", username, http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := forwardauth.New(time.Hour, &fakeAuthorizer{allow: true}, configuration.StorageConfiguration{})
			require.NoError(t, err)
			h := withForwardAuthToken(cfg, handler, &fakeAuthenticator{}, slog.New(slog.DiscardHandler))(
				routeSessions(handler, slog.New(slog.DiscardHandler)),
			)
			tokens := make(map[string]forwardauth.Token)
			requests := make(map[string]*http.Request)
			for _, user := range []string{username, invalidUsername} {
				requests[user], tokens[user] = createRequest(t, handler, user, cfg.CookieName, cfg.Key, http.MethodDelete, tt.path)
			}
			req := requests[username]
			req.URL.Path = cmp.Or(tt.path, "/session/"+tokens[tt.username].SessionID)
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, tt.want, resp.Code)

			count, _ := handler.Len(t.Context())
			if resp.Code == http.StatusNoContent {
				assert.Equal(t, 1, count)
			} else {
				assert.Equal(t, 2, count)
			}
		})
	}
}

func createRequest(
	tb testing.TB,
	mgr *forwardauth.Handler,
	username string,
	cookieName string,
	secret string,
	method string,
	url string,
) (*http.Request, forwardauth.Token) {
	// create the session
	tok, err := mgr.CreateSession(tb.Context(), provider.Identity{Email: username}, nil)
	require.NoError(tb, err)

	// sign the token
	rawToken, _ := tok.Sign([]byte(secret))

	req, _ := http.NewRequest(method, url, nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: rawToken})

	return req, tok
}
