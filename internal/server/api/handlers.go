package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/cache"
	"github.com/clambin/forward-auth/internal/server/middleware"
)

type Authenticator interface {
	middleware.Authenticator
	ListSessions(ctx context.Context, email string) (map[string]authn.Session, error)
	GetSession(ctx context.Context, sessionID string) (authn.Session, error)
	DeleteSession(ctx context.Context, id string) error
}

var _ Authenticator = (*authn.Authenticator)(nil)

func Handler(cookieName string, authenticator Authenticator, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/sessions", sessionsHandler(authenticator, logger.With(slog.String("handler", "sessions"))))
	mux.Handle("GET /session/{id}", getSessionHandler(authenticator))
	mux.Handle("DELETE /session/{id}", deleteSessionHandler(authenticator))
	return middleware.WithSessionValidation(cookieName, authenticator, true)(mux)
}

func sessionsHandler(authenticator Authenticator, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// session validation runs in struct mode, so this is only called if the session is valid
		validationResult, _ := middleware.SessionFromCtx(r.Context())
		// TODO: either we handle this in the service layer, or here.
		logger.Debug("got validation result", slog.Any("session", validationResult))
		userSessions, err := authenticator.ListSessions(r.Context(), validationResult.Session.UserInfo.Email)
		if err != nil {
			http.Error(w, "failed to list sessions", http.StatusInternalServerError)
			return
		}
		logger.Debug("got user sessions", slog.Any("sessions", userSessions))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userSessions)
	})
}

func getSessionHandler(authenticator Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// session validation runs in struct mode, so this is only called if the session is valid
		validationResult, _ := middleware.SessionFromCtx(r.Context())
		sessionID := r.PathValue("id")
		session, err := authenticator.GetSession(r.Context(), sessionID)
		if errors.Is(err, cache.ErrNotFound) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "failed to get session", http.StatusInternalServerError)
			return
		}
		if session.UserInfo.Email != validationResult.Session.UserInfo.Email {
			http.Error(w, "session does not belong to the user", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(session)
	})
}

func deleteSessionHandler(authenticator Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// session validation runs in struct mode, so this is only called if the session is valid
		validationResult, _ := middleware.SessionFromCtx(r.Context())
		sessionID := r.PathValue("id")
		session, err := authenticator.GetSession(r.Context(), sessionID)
		if errors.Is(err, cache.ErrNotFound) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "failed to get session", http.StatusInternalServerError)
			return
		}
		if session.UserInfo.Email != validationResult.Session.UserInfo.Email {
			http.Error(w, "session does not belong to the user", http.StatusForbidden)
			return
		}

		if err = authenticator.DeleteSession(r.Context(), sessionID); err != nil {
			http.Error(w, "failed to delete session", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
