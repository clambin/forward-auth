package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/clambin/forward-auth/internal/auth"
	"github.com/clambin/forward-auth/internal/auth/authn"
	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

type ForwardAuth interface {
	ValidateSession(ctx context.Context, sessionID string, url *url.URL) (authn.UserInfo, error)
	DeleteSession(ctx context.Context, sessionID string) error
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state string, code string) (authn.UserInfo, string, string, time.Duration, error)
}

type Configuration struct {
	Addr       string `yaml:"addr"`
	CookieName string `yaml:"cookieName"`
	Domain     string `yaml:"domain"`
}

var DefaultConfiguration = Configuration{
	Addr:       ":8080",
	CookieName: "forward-auth-session",
}

var _ ForwardAuth = (*auth.ForwardAuthServer)(nil)

func New(
	configuration Configuration,
	forwardAuth ForwardAuth,
	redisClient RedisClient,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	forwardAuthMux := http.NewServeMux()
	forwardAuthMux.Handle("/", forwardAuthHandler(
		configuration.CookieName,
		forwardAuth,
		logger.With(slog.String("handler", "forwardAuth")),
	))
	forwardAuthMux.Handle("/_oauth/logout", logoutHandler(
		configuration.CookieName,
		configuration.Domain,
		forwardAuth,
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
				forwardAuth,
				logger.With("handler", "login"),
			),
		),
	))
	mux.Handle("/healthz", healthCheckHandler(redisClient, logger.With("handler", "healthCheck")))

	return mux
}
