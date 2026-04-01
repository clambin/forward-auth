package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

type Authenticator interface {
	Validate(ctx context.Context, sessionID string) (*authn.Session, error)
	Close(ctx context.Context, sessionID string) error
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state string, code string) (*authn.Session, string, string, time.Duration, error)
}

var _ Authenticator = (*authn.Authenticator)(nil)

type Authorizer interface {
	Allow(url *url.URL, user string) bool
}

var _ Authorizer = (*authz.Authorizer)(nil)

func New(
	configuration configuration.ServerConfiguration,
	authenticator Authenticator,
	authorizer Authorizer,
	redisClient RedisClient,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	forwardAuthMux := http.NewServeMux()
	forwardAuthMux.Handle("/", forwardAuthHandler(
		configuration.CookieName,
		authenticator,
		authorizer,
		logger.With(slog.String("handler", "forwardAuth")),
	))
	forwardAuthMux.Handle("/_oauth/logout", logoutHandler(
		configuration.CookieName,
		configuration.Domain,
		authenticator,
		logger.With(slog.String("handler", "logout")),
	))

	mux.Handle("/", metrics.mw("forwardAuth")(
		forwardAuthMiddleware()(
			withRequestLogger(logger)(forwardAuthMux),
		),
	))
	mux.Handle("/_oauth", metrics.mw("login")(
		withRequestLogger(logger)(
			loginHandler(
				configuration.CookieName,
				configuration.Domain,
				authenticator,
				logger.With("handler", "login"),
			),
		),
	))
	mux.Handle("/healthz", healthCheckHandler(redisClient, logger.With("handler", "healthCheck")))

	return mux
}
