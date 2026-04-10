package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/server/web"
	"github.com/clambin/forward-auth/internal/sessions"
	"github.com/redis/go-redis/v9"
)

type SessionManager interface {
	Middleware(cookieName string, strict bool) func(http.Handler) http.Handler
	Get(ctx context.Context, id string) (sessions.Session, error)
	Add(ctx context.Context, userInfo provider.UserInfo, userAgent string) (string, error)
	Delete(ctx context.Context, id string) error
	TTL() time.Duration
	List(ctx context.Context) (map[string]sessions.Session, error)
}

var _ SessionManager = (*sessions.Manager)(nil)

type Authenticator interface {
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state, code string) (provider.UserInfo, string, error)
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

func New(
	cfg configuration.ServerConfiguration,
	sessionManager SessionManager,
	authenticator Authenticator,
	authorizer Authorizer,
	redisClient RedisClient,
	metrics Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/api/auth/forwardauth",
		metrics.InstrumentedHandler("forwardauth")(
			sessionManager.Middleware(cfg.CookieName, false)(
				forwardAuthHandler(authenticator, authorizer, logger.With(slog.String("handler", "forwardAuth"))),
			),
		),
	)
	mux.Handle("/api/auth/login",
		metrics.InstrumentedHandler("login")(
			loginHandler(cfg.CookieName, cfg.Domain, authenticator, sessionManager, logger.With(slog.String("handler", "login"))),
		),
	)

	sessionMux := http.NewServeMux()
	sessionMux.Handle("GET /api/sessions/list",
		getSessionsHandler(sessionManager, logger.With(slog.String("handler", "getSessions"))),
	)
	sessionMux.Handle("DELETE /api/sessions/session/{id}",
		deleteSessionHandler(sessionManager, logger.With(slog.String("handler", "deleteSession"))),
	)
	mux.Handle("/api/sessions/",
		metrics.InstrumentedHandler("session")(
			sessionManager.Middleware(cfg.CookieName, true)(
				sessionMux,
			),
		),
	)

	mux.Handle("/", web.New())
	mux.Handle("/healthz", healthCheckHandler(redisClient, logger.With("handler", "healthCheck")))

	return mux
}
