package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/server/api"
	"github.com/clambin/forward-auth/internal/server/forwardauth"
	"github.com/clambin/forward-auth/internal/server/web"
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

	mux.Handle("/forwardAuth",
		//withRequestLogger(logger)(
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
		//),
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

	mux.Handle("/",
		withRequestLogger(logger)(
			web.New(),
		))
	return mux
}

// withRequestLogger logs the request method, path, and duration.
func withRequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lw := &loggingResponseWriter{ResponseWriter: w}
			start := time.Now()
			next.ServeHTTP(lw, r)
			logger.Debug("request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", lw.code),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}

var _ http.ResponseWriter = (*loggingResponseWriter)(nil)

type loggingResponseWriter struct {
	http.ResponseWriter
	code int
}

func (l *loggingResponseWriter) WriteHeader(statusCode int) {
	l.code = statusCode
	l.ResponseWriter.WriteHeader(statusCode)
}
