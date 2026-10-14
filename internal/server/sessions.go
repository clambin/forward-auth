package server

import (
	"cmp"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/forwardauth"
)

func sessionsRoutes(
	cfg configuration.ServerConfiguration,
	handler *forwardauth.Handler,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /list", handleListSessions(handler, logger.With("handler", "listSessions")))
	mux.Handle("DELETE /session/{id}", handleDeleteSession(handler, logger.With("handler", "deleteSession")))

	return WithForwardAuthToken(cfg.CookieName, []byte(cfg.Key), StrictTokenMode)(mux)
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
		// get the token, which contains the user email.
		// handleSessions runs WithForwardAuthToken in strict mode, so we can trust the token is present and valid.
		token, _ := TokenFromRequest(r)

		// list sessions for the authenticated user
		sessions, err := handler.List(r.Context(), token.Identity.Email)
		if err != nil {
			logger.Error("failed to list sessions", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// write the response
		response := make([]listSessionsResponseItem, len(sessions))
		for i := range sessions {
			response[i] = listSessionsResponseItem{
				SessionID: sessions[i].ID,
				Identity:  sessions[i].Identity,
				LastSeen:  cmp.Or(sessions[i].RotatedAt, sessions[i].IssuedAt),
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
		// get the token, which contains the user email.
		// handleSessions runs WithForwardAuthToken in strict mode, so we can trust the token is present and valid.
		token, _ := TokenFromRequest(r)

		// if session id is missing, the http router will not match to this route and sends a 404 directly.
		id := r.PathValue("id")
		// Delete checks that the session is associated with the user
		username := token.Identity.Email
		if err := handler.DeleteSession(r.Context(), username, id); err != nil {
			if errors.Is(err, forwardauth.ErrSessionNotFound) {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			logger.Error("failed to delete session", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logger.Info("deleted session", slog.String("username", username))
		w.WriteHeader(http.StatusNoContent)
	})
}
