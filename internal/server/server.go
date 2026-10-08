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
	"github.com/redis/go-redis/v9"
)

type Authenticator interface {
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state, code string) (provider.Identity, string, error)
}

var _ Authenticator = (*authn.Authenticator)(nil)

type Authorizer interface {
	Allow(url *url.URL, user string) bool
	GroupsForUser(email string) []string
}

var _ Authorizer = (*authz.Authorizer)(nil)

type Metrics interface {
	InstrumentedHandler(label string) func(http.Handler) http.Handler
}

type RedisClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

// New returns a new http.Handler that serves all API endpoints and the web frontend.
func New(
	cfg configuration.ServerConfiguration,
	tokenManager *session.Manager,
	authenticator Authenticator,
	authorizer Authorizer,
	redisClient RedisClient,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/api/auth/forwardauth",
		metrics.InstrumentedHandler("forwardauth")(
			handleForwardAuth(
				cfg.CookieName,
				[]byte(cfg.Key),
				cfg.Domain,
				tokenManager,
				authenticator,
				authorizer,
				logger.With(slog.String("handler", "forwardAuth")),
			),
		),
	)
	mux.Handle("/api/auth/login",
		metrics.InstrumentedHandler("login")(
			handleLogin(
				cfg.CookieName,
				[]byte(cfg.Key),
				cfg.Domain,
				tokenManager,
				authenticator,
				logger.With(slog.String("handler", "login")),
			),
		),
	)

	mux.Handle("/api/sessions/", http.StripPrefix("/api/sessions", handleSessions(
		tokenManager,
		logger,
	)))

	mux.Handle("/", web.New())
	mux.Handle("/healthz", healthCheckHandler(redisClient, logger.With("handler", "healthCheck")))

	return mux
}
