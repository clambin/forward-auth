package v1

import (
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"

	"github.com/clambin/forward-auth/internal/cache"
	"github.com/clambin/forward-auth/internal/server/forwardauth"
	"github.com/clambin/forward-auth/internal/sessions"
)

func getSessionsHandler(sessionManager forwardauth.SessionManager, _ *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// session validation runs in strict mode, so handler is only called if the session is valid
		_, session, _ := sessions.SessionFromCtx(r.Context())
		allSessions, err := sessionManager.List(r.Context())
		if err != nil {
			http.Error(w, "failed to list sessions", http.StatusInternalServerError)
			return
		}
		// only return sessions belonging to the user
		userSessions := maps.Clone(allSessions)
		maps.DeleteFunc(userSessions, func(k string, v sessions.Session) bool {
			return v.UserInfo.Email != session.UserInfo.Email
		})
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(userSessions)
	})
}

func deleteSessionHandler(sessionManager forwardauth.SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// session validation runs in struct mode, so this is only called if the session is valid
		_, mySession, _ := sessions.SessionFromCtx(r.Context())
		sessionID := r.PathValue("id")
		session, err := sessionManager.Get(r.Context(), sessionID)
		if errors.Is(err, cache.ErrNotFound) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "failed to get session", http.StatusInternalServerError)
			return
		}
		if session.UserInfo.Email != mySession.UserInfo.Email {
			http.Error(w, "session does not belong to the user", http.StatusForbidden)
			return
		}
		if err = sessionManager.Delete(r.Context(), sessionID); err != nil {
			http.Error(w, "failed to delete session", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
