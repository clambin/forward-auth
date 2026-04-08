package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// WithRequestLogger logs the request method, path, and duration.
func WithRequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
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
