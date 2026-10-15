package healthcheck

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/redis/go-redis/v9"
)

type RedisClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
	Close() error
}

// Handler returns a healthCheck handler. If the Redis client is not nil, it pings the server.
func Handler(c RedisClient, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c == nil {
			return
		}
		if err := c.Ping(r.Context()).Err(); err != nil {
			logger.Warn("failed to ping redis", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}
