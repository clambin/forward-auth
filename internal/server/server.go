package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/forwardauth"
	"github.com/clambin/forward-auth/internal/server/web"
)

const (
	loginPath = "/api/auth/login"
)

type Authenticator interface {
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state, code string) (provider.Identity, string, error)
}

var _ Authenticator = (*authn.Authenticator)(nil)

type Metrics interface {
	InstrumentedHandler(label string) func(http.Handler) http.Handler
}

// New returns a new http.Handler that serves all API endpoints and the web frontend.
func New(
	cfg configuration.ServerConfiguration,
	handler *forwardauth.Handler,
	authenticator Authenticator,
	metrics Metrics,
	healthzHandler http.Handler,
	logger *slog.Logger,
) (http.Handler, http.Handler) {
	return routeInternal(cfg, handler, authenticator, metrics, healthzHandler, logger),
		routeExternal(cfg, handler, authenticator, metrics, logger)
}

func routeInternal(
	cfg configuration.ServerConfiguration,
	forwardAuthHandler *forwardauth.Handler,
	authenticator Authenticator,
	metrics Metrics,
	healthCheck http.Handler,
	logger *slog.Logger,
) http.Handler {
	// internal services
	mux := http.NewServeMux()
	mux.Handle(cfg.HealthPath, healthCheck)
	mux.Handle("/",
		metrics.InstrumentedHandler("forwardauth")(
			withForwardAuthToken(cfg.CookieName, []byte(cfg.Key), laxTokenMode)(
				handleForwardAuth(cfg, forwardAuthHandler, authenticator, logger.With("handler", "forwardAuth")),
			),
		),
	)
	return mux
}

func routeExternal(
	cfg configuration.ServerConfiguration,
	handler *forwardauth.Handler,
	authenticator Authenticator,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(loginPath,
		metrics.InstrumentedHandler("login")(
			handleLogin(
				cfg,
				handler,
				authenticator,
				logger.With("handler", "login"),
			),
		),
	)
	authenticatedMux := http.NewServeMux()
	authenticatedMux.Handle("/api/sessions/",
		metrics.InstrumentedHandler("api")(
			http.StripPrefix("/api/sessions",
				routeSessions(
					handler,
					logger,
				),
			),
		),
	)
	authenticatedMux.Handle("/",
		metrics.InstrumentedHandler("web")(
			web.New(),
		),
	)
	mux.Handle("/", withForwardAuthToken(cfg.CookieName, []byte(cfg.Key), strictTokenMode)(
		authenticatedMux,
	))
	return mux
}

func routeSessions(
	handler *forwardauth.Handler,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /list", handleListSessions(handler, logger.With("handler", "listSessions")))
	mux.Handle("DELETE /session/{id}", handleDeleteSession(handler, logger.With("handler", "deleteSession")))
	return mux
}
