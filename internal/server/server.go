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
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/api/auth/forwardauth",
		metrics.InstrumentedHandler("forwardauth")(
			handleForwardAuth(
				cfg,
				handler,
				authenticator,
				logger.With(slog.String("handler", "forwardAuth")),
			),
		),
	)
	mux.Handle("/api/auth/login",
		metrics.InstrumentedHandler("login")(
			handleLogin(
				cfg,
				handler,
				authenticator,
				logger.With(slog.String("handler", "login")),
			),
		),
	)

	mux.Handle("/api/sessions/",
		http.StripPrefix("/api/sessions",
			sessionsRoutes(cfg, handler, logger),
		),
	)

	mux.Handle("/", web.New())

	return mux
}
