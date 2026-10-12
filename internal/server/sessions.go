package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/forwardauth"
)

func handleSessions(
	handler *forwardauth.Handler,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /list", handleListSessions(handler, logger.With("handler", "listSessions")))
	mux.Handle("DELETE /session/{id}", handleDeleteSession(handler, logger.With("handler", "deleteSession")))

	return ensureUserEmailHeader(mux)
}

type listSessionsResponseItem struct {
	SessionID string            `json:"id"`
	Identity  provider.Identity `json:"user_info"`
	LastSeen  time.Time         `json:"last_seen"`
	UserAgent string            `json:"user_agent"`
}

func handleListSessions(
	handler *forwardauth.Handler,
	logger *slog.Logger,

) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions, err := handler.List(r.Context(), r.Header.Get(forwardedUserEmailHeader))
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
	handler *forwardauth.Handler,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Note: we rely on the forwarded user email header to identify the user
		// ListSessions and DeleteSessions are only accessed after forward-auth has run
		// (this is configured by the HTTPRoute, so we can trust the user email header)
		username := r.Header.Get(forwardedUserEmailHeader)
		// if session id is missing, the http router will not match to this route and sends a 404 directly.
		id := r.PathValue("id")
		// Delete checks that the session is associated with the user
		err := handler.DeleteSession(r.Context(), username, id)
		logger.Debug("deleting session", "username", username, "id", id, "err", err)
		if err != nil {
			if errors.Is(err, forwardauth.ErrSessionNotFound) {
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

// ensureUserEmailHeader is a middleware that ensures the forwarded user email header is present
// Note: handleSessions relies on the forwarded user email header to identify the user, rather than the JWT.
// ListSessions and DeleteSessions are only accessed after forward-auth has run
// (this is configured by the HTTPRoute, so we can trust the user email header).
func ensureUserEmailHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if username := r.Header.Get(forwardedUserEmailHeader); username == "" {
			http.Error(w, "missing X-Forwarded-User header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
