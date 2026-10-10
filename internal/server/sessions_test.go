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
	mgr, err := session.New(time.Hour, configuration.StorageConfiguration{})
	require.NoError(t, err)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "test")
	req.Header.Set(forwardedUserEmailHeader, "test@example.com")
	_, err = mgr.CreateSession(t.Context(), provider.Identity{Email: "test@example.com"}, req)
	require.NoError(t, err)

	h := handleListSessions(mgr, slog.New(slog.DiscardHandler))
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))

	var sessions []listSessionsResponseItem
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sessions))
	require.Len(t, sessions, 1)
	assert.Equal(t, "test@example.com", sessions[0].Identity.Email)
	assert.NotZero(t, "test@example.com", sessions[0].SessionID)
	assert.Equal(t, "test", sessions[0].UserAgent)
}

func TestHandleDeleteSession(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		userHeader string
		want       int
	}{
		{"missing header", "", "", http.StatusForbidden},
		{"missing session id", "/session/", "test@example.com", http.StatusNotFound},
		{"wrong session id", "/session/invalid", "test@example.com", http.StatusNotFound},
		{"wrong user in header", "", "invalid@example.com", http.StatusNotFound},
		{"valid", "", "test@example.com", http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := session.New(time.Hour, configuration.StorageConfiguration{})
			require.NoError(t, err)

			tok, err := mgr.CreateSession(t.Context(), provider.Identity{Email: "test@example.com"}, &http.Request{})
			require.NoError(t, err)

			h := handleSessions(mgr, slog.New(slog.DiscardHandler))

			req, _ := http.NewRequest(http.MethodDelete, cmp.Or(tt.path, "/session/"+tok.SessionID), nil)
			if tt.userHeader != "" {
				req.Header.Set(forwardedUserEmailHeader, tt.userHeader)
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, tt.want, resp.Code)

			count, _ := mgr.Len(t.Context())
			if resp.Code == http.StatusNoContent {
				assert.Equal(t, 0, count)
			} else {
				assert.Equal(t, 1, count)
			}
		})
	}
}
