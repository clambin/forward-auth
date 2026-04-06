package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"

	"github.com/clambin/forward-auth/internal/cache"
	"github.com/clambin/forward-auth/internal/sessions"
)

type SessionManager interface {
	Middleware(cookieName string, strict bool) func(handler http.Handler) http.Handler
	List(ctx context.Context) (map[string]sessions.Session, error)
	Get(ctx context.Context, id string) (sessions.Session, error)
	Delete(ctx context.Context, id string) error
}

var _ SessionManager = (*sessions.Manager)(nil)

func Handler(cookieName string, sessionManager SessionManager, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/sessions", getSessionsHandler(sessionManager, logger.With(slog.String("handler", "getSessions"))))
	mux.Handle("GET /session/{id}", getSessionHandler(sessionManager))
	mux.Handle("DELETE /session/{id}", deleteSessionHandler(sessionManager))
	return sessionManager.Middleware(cookieName, true)(mux)
}

func getSessionsHandler(sessionManager SessionManager, _ *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// session validation runs in struct mode, so handler is only called if the session is valid
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

func getSessionHandler(sessionManager SessionManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// session validation runs in strict mode, so this is only called if the session is valid
		_, mySession, _ := sessions.SessionFromCtx(r.Context())
		// get the requested session
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
		// only return sessions belonging to the user
		if session.UserInfo.Email != mySession.UserInfo.Email {
			http.Error(w, "session does not belong to the user", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(session)
	})
}

func deleteSessionHandler(sessionManager SessionManager) http.Handler {
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
