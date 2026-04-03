package server

import (
	"log/slog"
	"net/http"
)

func healthCheckHandler(c RedisClient, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c != nil {
			if err := c.Ping(r.Context()).Err(); err != nil {
				logger.Warn("failed to ping redis", "error", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	})
}
