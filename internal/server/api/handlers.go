package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/cache"
	"github.com/clambin/forward-auth/internal/server/middleware"
)

type Authenticator interface {
	middleware.Authenticator
	ListSessions(ctx context.Context) (map[string]authn.Session, error)
	GetSession(ctx context.Context, id string) (authn.Session, error)
	DeleteSession(ctx context.Context, id string) error
}

var _ Authenticator = (*authn.Authenticator)(nil)

func Handler(cookieName string, authenticator Authenticator, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/sessions", getSessionsHandler(authenticator, logger.With(slog.String("handler", "getSessions"))))
	mux.Handle("GET /session/{id}", getSessionHandler(authenticator))
	mux.Handle("DELETE /session/{id}", deleteSessionHandler(authenticator))
	return middleware.WithSessionValidation(cookieName, authenticator, true)(mux)
}

func getSessionsHandler(authenticator Authenticator, _ *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// session validation runs in struct mode, so handler is only called if the session is valid
		validationResult, _ := middleware.SessionFromCtx(r.Context())
		allSessions, err := authenticator.ListSessions(r.Context())
		if err != nil {
			http.Error(w, "failed to list sessions", http.StatusInternalServerError)
			return
		}
		// only return sessions belonging to the user
		userSessions := maps.Clone(allSessions)
		maps.DeleteFunc(userSessions, func(k string, v authn.Session) bool {
			return v.UserInfo.Email != validationResult.Session.UserInfo.Email
		})
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(userSessions)
	})
}

func getSessionHandler(authenticator Authenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		// session validation runs in struct mode, so this is only called if the session is valid
		validationResult, _ := middleware.SessionFromCtx(r.Context())
		if session.UserInfo.Email != validationResult.Session.UserInfo.Email {
			http.Error(w, "session does not belong to the user", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(session)
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
