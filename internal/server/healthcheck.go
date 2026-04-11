package server

import (
	"log/slog"
	"net/http"
)

// healthCheckHandler returns a healthCheck handler. If the Redis client is not nil, it pings the server.
func healthCheckHandler(c RedisClient, logger *slog.Logger) http.Handler {
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
