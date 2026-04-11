package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"

	"github.com/clambin/forward-auth/internal/cache"
	"github.com/clambin/forward-auth/internal/sessions"
)

// getSessionsHandler returns a list of all sessions for the user.
func getSessionsHandler(sessionManager *sessions.Manager, _ *slog.Logger) http.Handler {
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

// deleteSessionHandler deletes a session. If the requested session does not belong to the user, the request is rejected.
func deleteSessionHandler(sessionManager *sessions.Manager, logger *slog.Logger) http.Handler {
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
			logger.Warn("refused to delete session: session does not belong to the user",
				slog.String("sessionID", sessionID),
				slog.String("request email", mySession.UserInfo.Email),
				slog.String("session email", session.UserInfo.Email),
			)
			http.Error(w, "session does not belong to the user", http.StatusForbidden)
			return
		}
		if err = sessionManager.Delete(r.Context(), sessionID); err != nil {
			logger.Error("failed to delete session", "err", err)
			http.Error(w, "failed to delete session", http.StatusInternalServerError)
			return
		}
		logger.Debug("deleted session", "sessionID", sessionID)
		w.WriteHeader(http.StatusNoContent)
	})
}
