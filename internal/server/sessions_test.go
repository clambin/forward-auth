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
	"github.com/clambin/forward-auth/internal/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListSessionsHandler(t *testing.T) {
	tests := []struct {
		name             string
		target           string
		addCookie        bool
		wantCode         int
		wantSessionCount int
	}{
		{"valid", "/api/sessions/list", true, http.StatusOK, 1},
		{"invalid", "/api/sessions/list", false, http.StatusUnauthorized, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionManager, _ := sessions.New(5*time.Minute, configuration.StorageConfiguration{})
			sessionID, _ := sessionManager.Add(t.Context(), provider.UserInfo{Email: "foo@example.com"}, "")
			const cookieName = "session"

			s := New(
				configuration.ServerConfiguration{CookieName: cookieName, Domain: "example.com"},
				sessionManager,
				nil,
				nil,
				&fakeRedisClient{},
				&fakeMetrics{},
				slog.New(slog.DiscardHandler),
			)

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			if tt.addCookie {
				req.AddCookie(&http.Cookie{Name: cookieName, Value: sessionID})
			}
			resp := httptest.NewRecorder()
			s.ServeHTTP(resp, req)
			require.Equal(t, tt.wantCode, resp.Code)

			if tt.wantCode != http.StatusOK {
				return
			}

			var l map[string]sessions.Session
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&l))
			assert.Len(t, l, tt.wantSessionCount)
		})
	}
}

func TestDeleteSessionHandler(t *testing.T) {
	sessionManager, _ := sessions.New(5*time.Minute, configuration.StorageConfiguration{})
	sessionIDFoo, _ := sessionManager.Add(t.Context(), provider.UserInfo{Email: "foo@example.com"}, "")
	sessionIDFoo2, _ := sessionManager.Add(t.Context(), provider.UserInfo{Email: "foo@example.com"}, "")
	sessionIDBar, _ := sessionManager.Add(t.Context(), provider.UserInfo{Email: "bar@example.com"}, "")

	tests := []struct {
		name     string
		target   string
		wantCode int
	}{
		{"success", "/api/sessions/session/" + sessionIDFoo, http.StatusNoContent},
		{"unauthorized session", "/api/sessions/session/" + sessionIDBar, http.StatusForbidden},
		{"invalid session", "/api/sessions/session/invalid", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cookieName = "session"
			s := New(
				configuration.ServerConfiguration{CookieName: cookieName, Domain: "example.com"},
				sessionManager,
				nil,
				nil,
				&fakeRedisClient{},
				&fakeMetrics{},
				slog.New(slog.DiscardHandler),
			)

			req := httptest.NewRequest(http.MethodDelete, tt.target, nil)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: sessionIDFoo2})
			resp := httptest.NewRecorder()
			s.ServeHTTP(resp, req)
			require.Equal(t, tt.wantCode, resp.Code)
		})
	}
}
