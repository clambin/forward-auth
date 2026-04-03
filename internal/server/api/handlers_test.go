package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/cache"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListSessionsHandler(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		sessionID string
		wantCode  int
		wantList  map[string]authn.Session
	}{
		{"valid", "/sessions", "1234", http.StatusOK, map[string]authn.Session{
			"1234": {UserInfo: provider.UserInfo{Email: "foo@example.com"}},
		}},
		{"invalid", "/sessions", "invalid", http.StatusForbidden, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := fakeAuthenticator{
				sessions: map[string]authn.Session{
					"1234": {UserInfo: provider.UserInfo{Email: "foo@example.com"}},
					"5678": {UserInfo: provider.UserInfo{Email: "bar@example.com"}},
				},
			}
			const cookieName = "session"
			h := Handler(cookieName, &auth, slog.New(slog.DiscardHandler))

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: tt.sessionID})
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, tt.wantCode, resp.Code)

			if tt.wantCode != http.StatusOK {
				return
			}

			var l map[string]authn.Session
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&l))
			assert.Equal(t, tt.wantList, l)
		})
	}
}

func TestGetSessionHandler(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantCode int
	}{
		{"success", "/session/1234", http.StatusOK},
		{"unauthorized session", "/session/5678", http.StatusForbidden},
		{"invalid session", "/session/invalid", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := fakeAuthenticator{
				sessions: map[string]authn.Session{
					"1234": {UserInfo: provider.UserInfo{Email: "foo@example.com"}},
					"5678": {UserInfo: provider.UserInfo{Email: "bar@example.com"}},
				},
			}
			const cookieName = "session"
			h := Handler(cookieName, &auth, slog.New(slog.DiscardHandler))

			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: "1234"})
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, tt.wantCode, resp.Code)
		})
	}
}

func TestDeleteSessionHandler(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantCode int
	}{
		{"success", "/session/1234", http.StatusNoContent},
		{"unauthorized session", "/session/5678", http.StatusForbidden},
		{"invalid session", "/session/invalid", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := fakeAuthenticator{
				sessions: map[string]authn.Session{
					"1234": {UserInfo: provider.UserInfo{Email: "foo@example.com"}},
					"5678": {UserInfo: provider.UserInfo{Email: "bar@example.com"}},
				},
			}
			const cookieName = "session"
			h := Handler(cookieName, &auth, slog.New(slog.DiscardHandler))

			req := httptest.NewRequest(http.MethodDelete, tt.target, nil)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: "1234"})
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, tt.wantCode, resp.Code)
		})
	}

}

var _ Authenticator = &fakeAuthenticator{}

type fakeAuthenticator struct {
	sessions map[string]authn.Session
}

func (f fakeAuthenticator) Validate(_ context.Context, sessionID string) (*authn.Session, error) {
	if session, ok := f.sessions[sessionID]; ok {
		return &session, nil
	}
	return nil, cache.ErrNotFound
}

func (f fakeAuthenticator) ListSessions(_ context.Context, email string) (map[string]authn.Session, error) {
	sessions := maps.Clone(f.sessions)
	maps.DeleteFunc(sessions, func(k string, v authn.Session) bool {
		return v.UserInfo.Email != email
	})
	return sessions, nil
}

func (f fakeAuthenticator) GetSession(_ context.Context, sessionID string) (authn.Session, error) {
	if session, ok := f.sessions[sessionID]; ok {
		return session, nil
	}
	return authn.Session{}, cache.ErrNotFound
}

func (f fakeAuthenticator) DeleteSession(_ context.Context, sessionID string) error {
	if _, ok := f.sessions[sessionID]; !ok {
		return cache.ErrNotFound
	}
	delete(f.sessions, sessionID)
	return nil
}
