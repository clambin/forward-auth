package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/server/web"
	"github.com/clambin/forward-auth/internal/session"
)

const (
	loginPath = "/api/auth/login"
)

type Authenticator interface {
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state, code string) (provider.Identity, string, error)
}

var _ Authenticator = (*authn.Authenticator)(nil)

type Authorizer interface {
	Allow(u *url.URL, user string) bool
	GroupsForUser(email string) []string
}

var _ Authorizer = (*authz.Authorizer)(nil)

type Metrics interface {
	InstrumentedHandler(label string) func(http.Handler) http.Handler
}

// New returns a new http.Handler that serves all API endpoints and the web frontend.
func New(
	cfg configuration.ServerConfiguration,
	handler session.Sessions,
	authorizer Authorizer,
	metrics Metrics,
	healthzHandler http.Handler,
	logger *slog.Logger,
) (http.Handler, http.Handler) {
	return routeInternal(cfg, handler, authorizer, metrics, healthzHandler, logger),
		routeExternal(handler, metrics, logger)
}

func routeInternal(
	cfg configuration.ServerConfiguration,
	sessions session.Sessions,
	authorizer Authorizer,
	metrics Metrics,
	healthCheck http.Handler,
	logger *slog.Logger,
) http.Handler {
	// internal services
	mux := http.NewServeMux()
	mux.Handle(cfg.HealthPath, healthCheck)
	mux.Handle("/",
		metrics.InstrumentedHandler("forwardauth")(
			withForwardAuthMiddleware()( // restore the request first, so the `sessions` middleware redirects for the correct request
				sessions.ServerMiddleware()(
					handleForwardAuth(authorizer, logger.With("handler", "forwardAuth")),
				),
			),
		),
	)
	return mux
}

func routeExternal(
	sessions session.Sessions,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(loginPath,
		metrics.InstrumentedHandler("login")(
			sessions.LoginHandler(), // TODO: logger for "login" handler
		),
	)
	mux.Handle("/api/sessions/",
		metrics.InstrumentedHandler("api")(
			http.StripPrefix("/api/sessions",
				sessions.ServerMiddleware()(
					routeSessions(
						sessions,
						logger.With(slog.String("handler", "sessions")),
					),
				),
			),
		),
	)
	mux.Handle("/",
		metrics.InstrumentedHandler("web")(
			web.New(),
		),
	)
	return mux
}

func routeSessions(
	handler session.Sessions,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /list", handleListSessions(handler, logger.With("handler", "listSessions")))
	mux.Handle("DELETE /session/{id}", handleDeleteSession(handler, logger.With("handler", "deleteSession")))
	return mux
}
