package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"uuid"

	"github.com/clambin/forward-auth/internal/forwardauth"
)

var ErrTokenExpired = errors.New("token expired")

type logCtx struct{}

// WithLogger adds a logger to the context of the request
func WithLogger(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), logCtx{}, logger)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithReqIDLogger is similar to WithLogger, but adds a unique Request ID to the logger
func WithReqIDLogger(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), logCtx{}, logger.With(slog.String("reqID", uuid.New().String())))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Logger returns the logger from the context of the request
func Logger(r *http.Request) *slog.Logger {
	logger, ok := r.Context().Value(logCtx{}).(*slog.Logger)
	if !ok {
		logger = slog.Default()
	}
	return logger
}

type tokenCtx struct{}
type parsedToken struct {
	token forwardauth.Token
	err   error
}

type TokenMode int

const (
	StrictTokenMode TokenMode = iota
	LaxTokenMode
)

// WithForwardAuthToken parses the JWT Token out of the request and adds it to the request's context.
// WithForwardAuthToken can operate in strict mode, rejecting a request that doesn't present a valid token,
// and lax mode, which will allow the request to continue even if the token is invalid.
func WithForwardAuthToken(cookieName string, secret []byte, mode TokenMode) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the cookie from the request
			var tok parsedToken
			tok.token, tok.err = tokenFromCookie(r, cookieName, secret)
			if tok.err == nil && tok.token.Expired() {
				tok.err = ErrTokenExpired
			}
			// in strict mode, reject the request if the token is invalid
			if tok.err != nil && mode == StrictTokenMode {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			// add the token to the request context
			ctx := context.WithValue(r.Context(), tokenCtx{}, tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func TokenFromRequest(r *http.Request) (forwardauth.Token, error) {
	tok, ok := r.Context().Value(tokenCtx{}).(parsedToken)
	if !ok {
		return forwardauth.Token{}, http.ErrNoCookie
	}
	return tok.token, tok.err
}
