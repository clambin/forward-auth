package server

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clambin/forward-auth/internal/auth"
	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

type ForwardAuth interface {
	ValidateSession(ctx context.Context, sessionID string, url *url.URL) (string, error)
	DeleteSession(ctx context.Context, sessionID string) error
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state string, code string) (string, string, string, time.Duration, error)
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

func New(configuration Configuration, forwardAuth ForwardAuth, redisClient RedisClient, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	route(mux, configuration, forwardAuth, redisClient, logger)
	return mux
}

func route(mux *http.ServeMux, configuration Configuration, forwardAuth ForwardAuth, redisClient RedisClient, logger *slog.Logger) {
	forwardAuthMux := http.NewServeMux()
	forwardAuthMux.Handle("/", forwardAuthHandler(
		configuration.CookieName,
		forwardAuth,
		logger.With("handler", "forwardAuth"),
	))
	forwardAuthMux.Handle("/_oauth/logout", logoutHandler(
		configuration.CookieName,
		configuration.Domain,
		forwardAuth,
		logger.With("handler", "logout"),
	))

	mux.Handle("/", forwardAuthMiddleware()(forwardAuthMux))
	mux.Handle("/_oauth", loginHandler(
		configuration.CookieName,
		configuration.Domain,
		forwardAuth,
		logger.With("handler", "login"),
	))
	mux.Handle("/healthz", healthCheckHandler(redisClient, logger.With("handler", "healthCheck")))
}

// forwardAuthMiddleware takes a request from the forwardAuth middleware and restores the original request method and URL.
func forwardAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.Clone(r.Context())
			r.Method, r.URL = originalRequest(r)
			next.ServeHTTP(w, r)
		})
	}
}

func originalRequest(r *http.Request) (string, *url.URL) {
	path := cmp.Or(r.Header.Get("X-Forwarded-Uri"), "/")
	var rawQuery string
	if n := strings.Index(path, "?"); n > 0 {
		rawQuery = path[n+1:]
		path = path[:n]
	}

	return cmp.Or(r.Header.Get("X-Forwarded-Method"), http.MethodGet), &url.URL{
		Scheme:   cmp.Or(r.Header.Get("X-Forwarded-Proto"), "https"),
		Host:     cmp.Or(r.Header.Get("X-Forwarded-Host"), ""),
		Path:     path,
		RawQuery: rawQuery,
	}
}
