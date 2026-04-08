package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/server/api/v1"
	"github.com/clambin/forward-auth/internal/server/forwardauth"
	"github.com/clambin/forward-auth/internal/server/middleware"
	"github.com/clambin/forward-auth/internal/server/web"
	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

func New(
	configuration configuration.ServerConfiguration,
	sessionManager forwardauth.SessionManager,
	authenticator forwardauth.Authenticator,
	authorizer forwardauth.Authorizer,
	redisClient RedisClient,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/api/v1/",
		metrics.mw("api.v1")(
			http.StripPrefix("/api/v1",
				v1.New(
					configuration.CookieName,
					configuration.Domain,
					authenticator,
					authorizer,
					sessionManager,
					logger.With("handler", "api"),
				),
			),
		),
	)

	mux.Handle("/",
		middleware.WithRequestLogger(logger)(
			web.New(),
		),
	)

	mux.Handle("/healthz", healthCheckHandler(redisClient, logger.With("handler", "healthCheck")))
	return mux
}
