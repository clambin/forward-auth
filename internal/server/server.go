package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/server/api"
	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

type Authenticator interface {
	Validate(ctx context.Context, sessionID string) (*authn.Session, error)
	InitiateLogin(ctx context.Context, url string) (string, error)
	Close(ctx context.Context, sessionID string) error
	ConfirmLogin(ctx context.Context, state, code string) (*authn.Session, string, string, time.Duration, error)
	api.Authenticator
}

var _ Authenticator = (*authn.Authenticator)(nil)

func New(
	configuration configuration.ServerConfiguration,
	authenticator Authenticator,
	authorizer Authorizer,
	redisClient RedisClient,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/", metrics.mw("forwardAuth")(
		withRequestLogger(logger)(
			ForwardAuthHandler(
				configuration.CookieName,
				configuration.Domain,
				authenticator,
				authorizer,
				logger.With("handler", "forwardAuth"),
			),
		),
	))

	mux.Handle("/_oauth", metrics.mw("login")(
		withRequestLogger(logger)(
			LoginHandler(
				configuration.CookieName,
				configuration.Domain,
				authenticator,
				logger.With("handler", "login"),
			),
		),
	))

	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", api.Handler(
		configuration.CookieName,
		authenticator,
		logger.With("handler", "api"),
	)))

	mux.Handle("/healthz", healthCheckHandler(redisClient, logger.With("handler", "healthCheck")))

	return mux
}
