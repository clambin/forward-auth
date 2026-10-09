package server

import (
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

	req, _ := http.NewRequest("GET", "/", nil)
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
