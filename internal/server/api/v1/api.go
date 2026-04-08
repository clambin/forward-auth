package v1

import (
	"log/slog"
	"net/http"

	"github.com/clambin/forward-auth/internal/server/forwardauth"
	"github.com/clambin/forward-auth/internal/server/middleware"
)

func New(
	cookieName string,
	domain string,
	authenticator forwardauth.Authenticator,
	authorizer forwardauth.Authorizer,
	sessionManager forwardauth.SessionManager,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/auth/", http.StripPrefix("/auth",
		routeAuth(cookieName, domain, authenticator, authorizer, sessionManager, logger),
	))
	mux.Handle("/sessions/", http.StripPrefix("/sessions",
		middleware.WithRequestLogger(logger)(
			routeSessions(cookieName, sessionManager, logger),
		),
	))
	return mux
}

func routeAuth(
	cookieName string,
	domain string,
	authenticator forwardauth.Authenticator,
	authorizer forwardauth.Authorizer,
	sessionManager forwardauth.SessionManager,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/forwardauth",
		sessionManager.Middleware(cookieName, false)(
			forwardAuthHandler(authenticator, authorizer, logger.With(slog.String("handler", "forwardAuth"))),
		),
	)
	mux.Handle("/login",
		loginHandler(cookieName, domain, authenticator, sessionManager, logger.With(slog.String("handler", "login"))),
	)
	return mux
}

func routeSessions(cookieName string, sessionManager forwardauth.SessionManager, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/list", getSessionsHandler(sessionManager, logger.With("handler", "getSessions")))
	mux.Handle("DELETE /session/{id}", deleteSessionHandler(sessionManager))
	return sessionManager.Middleware(cookieName, true)(mux)
}
