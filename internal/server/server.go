package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/server/api"
	"github.com/clambin/forward-auth/internal/server/forwardauth"
	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

type SessionManager interface {
	forwardauth.SessionManager
	api.SessionManager
}

func New(
	configuration configuration.ServerConfiguration,
	sessionManager SessionManager,
	authenticator forwardauth.Authenticator,
	authorizer forwardauth.Authorizer,
	redisClient RedisClient,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/",
		withRequestLogger(logger)(
			metrics.mw("forwardAuth")(
				forwardauth.AuthHandler(
					configuration.CookieName,
					configuration.Domain,
					sessionManager,
					authenticator,
					authorizer,
					logger.With("handler", "forwardAuth"),
				),
			),
		),
	)

	mux.Handle("/_oauth",
		withRequestLogger(logger)(
			metrics.mw("login")(
				forwardauth.LoginHandler(
					configuration.CookieName,
					configuration.Domain,
					authenticator,
					sessionManager,
					logger.With("handler", "login"),
				),
			),
		),
	)

	mux.Handle("/api/v1/",
		withRequestLogger(logger)(
			metrics.mw("api.v1")(
				http.StripPrefix("/api/v1",
					api.Handler(
						configuration.CookieName,
						sessionManager,
						logger.With("handler", "api"),
					),
				),
			),
		),
	)

	mux.Handle("/healthz", healthCheckHandler(redisClient, logger.With("handler", "healthCheck")))
	return mux
}
