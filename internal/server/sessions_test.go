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
	"github.com/clambin/forward-auth/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListSessions(t *testing.T) {
	const username = "test@example.com"

	cfg := configuration.ServerConfiguration{
		CookieName: "forward-auth-session",
		Key:        "secret",
	}

	sessions, err := session.New(
		time.Hour,
		cfg,
		configuration.StorageConfiguration{},
		nil,
		slog.New(slog.DiscardHandler),
	)
	require.NoError(t, err)
	_, err = sessions.CreateSession(t.Context(), provider.Identity{Email: username}, &http.Request{})
	require.NoError(t, err)

	h := routeSessions(sessions, slog.New(slog.DiscardHandler))

	req, _ := http.NewRequest(http.MethodGet, "/list", nil)
	req = session.SetAuthenticatedUser(req, provider.Identity{Email: username})
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var sessionList []listSessionsResponseItem
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sessionList))
	require.Len(t, sessionList, 1)
	assert.Equal(t, username, sessionList[0].Identity.Email)
	assert.NotZero(t, sessionList[0].SessionID)

	req, _ = http.NewRequest(http.MethodGet, "/list", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusUnauthorized, resp.Code)

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
		token    bool
		want     int
	}{
		{"missing session id in path", "/session/", username, true, http.StatusNotFound},
		{"wrong session id in path", "/session/invalid", username, true, http.StatusNotFound},
		{"no token", "", username, false, http.StatusUnauthorized},
		{"wrong user in token", "", invalidUsername, true, http.StatusNotFound},
		{"valid", "", username, true, http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := session.New(
				time.Hour,
				cfg,
				configuration.StorageConfiguration{},
				nil,
				slog.New(slog.DiscardHandler),
			)
			require.NoError(t, err)
			h := routeSessions(sessions, slog.New(slog.DiscardHandler))

			tokens := make(map[string]session.Token)
			for _, user := range []string{username, invalidUsername} {
				tokens[user], err = sessions.CreateSession(t.Context(), provider.Identity{Email: user}, &http.Request{})
				require.NoError(t, err)
			}

			req, _ := http.NewRequest(http.MethodDelete, cmp.Or(tt.path, "/session/"+tokens[tt.username].SessionID), nil)
			if tt.token {
				req = session.SetAuthenticatedUser(req, provider.Identity{Email: username})
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, tt.want, resp.Code)

			count, _ := sessions.Len(t.Context())
			if resp.Code == http.StatusNoContent {
				assert.Equal(t, 1, count)
			} else {
				assert.Equal(t, 2, count)
			}
		})
	}
}
