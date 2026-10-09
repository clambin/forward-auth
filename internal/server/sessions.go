package server

import (
	"encoding/json"
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
	mux.Handle("DELETE /session/{id}", handleDeleteSession(sessionManager))

	return mux
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
		username := r.Header.Get(forwardedUserEmailHeader)
		if username == "" {
			http.Error(w, "missing X-Forwarded-User header", http.StatusBadRequest)
			return
		}
		sessions, err := sessionManager.List(r.Context(), username)
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

func handleDeleteSession(_ *session.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//r.PathValue("id")
		//w.Write([]byte("delete session"))
	})
}
