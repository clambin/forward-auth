package server

import (
	"cmp"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

// originalRequest restores the original request method and URL from the Treaefik forwardAuthrequest headers.
// This allows us to route forwardAuth requests vs. logout requests (/_oauth/logout) to the correct handler.
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
