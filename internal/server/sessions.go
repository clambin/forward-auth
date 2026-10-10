package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/session"
)

func handleSessions(
	sessionManager *session.Manager,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /list", handleListSessions(sessionManager, logger.With("handler", "listSessions")))
	mux.Handle("DELETE /session/{id}", handleDeleteSession(sessionManager, logger.With("handler", "deleteSession")))

	return ensureUserEmailHeader(mux)
}

type listSessionsResponseItem struct {
	SessionID string            `json:"id"`
	Identity  provider.Identity `json:"user_info"`
	LastSeen  time.Time         `json:"last_seen"`
	UserAgent string            `json:"user_agent"`
}

func handleListSessions(
	sessionManager *session.Manager,
	logger *slog.Logger,

) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions, err := sessionManager.List(r.Context(), r.Header.Get(forwardedUserEmailHeader))
		if err != nil {
			logger.Error("failed to list sessions", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response := make([]listSessionsResponseItem, len(sessions))
		for i := range sessions {
			response[i] = listSessionsResponseItem{
				SessionID: sessions[i].ID,
				Identity:  sessions[i].Identity,
				LastSeen:  sessions[i].LastSeen,
				UserAgent: sessions[i].UserAgent,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err = json.NewEncoder(w).Encode(response); err != nil {
			logger.Error("failed to encode response", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handleDeleteSession(
	sessionManager *session.Manager,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ensureUserEmailHeader ensures that the forwardedUserEmailHeader is present in the request header.
		username := r.Header.Get(forwardedUserEmailHeader)
		// if session id is missing, the http router will not match to this route and sends a 404 directly.
		id := r.PathValue("id")
		logger.Debug("deleting session", "username", username, "id", id)
		err := sessionManager.Delete(r.Context(), username, id)
		if err != nil {
			if errors.Is(err, session.ErrSessionNotFound) {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			logger.Error("failed to delete session", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func ensureUserEmailHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if username := r.Header.Get(forwardedUserEmailHeader); username == "" {
			http.Error(w, "missing X-Forwarded-User header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
