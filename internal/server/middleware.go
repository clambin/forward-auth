package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/forwardauth"
)

type tokenCtx struct{}

// withForwardAuthToken parses the JWT Token from a request and adds it to the request's context.
// It can operate in strict mode, rejecting a request that doesn't present a valid token,
// or in lax mode, allowing the request to continue even if the token is invalid.
func withForwardAuthToken(cfg configuration.ServerConfiguration, handler *forwardauth.Handler, authenticator Authenticator, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// validate the token
			token, err := forwardAuth(w, r, cfg, handler, authenticator, logger)
			if err == nil {
				// add the token to the request context
				ctx := context.WithValue(r.Context(), tokenCtx{}, token)
				// call the next handler with the updated context
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		})
	}
}

func tokenFromRequest(r *http.Request) (forwardauth.Token, error) {
	tok, ok := r.Context().Value(tokenCtx{}).(forwardauth.Token)
	if !ok {
		return forwardauth.Token{}, http.ErrNoCookie
	}
	return tok, nil
}

func tokenFromCookie(r *http.Request, cookieName string, key []byte) (forwardauth.Token, error) {
	// get the jwt token
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return forwardauth.Token{}, err
	}
	// parse the token
	return forwardauth.ParseToken(cookie.Value, key)
}

func forwardAuth(
	w http.ResponseWriter,
	r *http.Request,
	cfg configuration.ServerConfiguration,
	handler *forwardauth.Handler,
	authenticator Authenticator,
	logger *slog.Logger,
) (forwardauth.Token, error) {
	token, err := tokenFromCookie(r, cfg.CookieName, []byte(cfg.Key))
	if err != nil {
		logger.Error("failed to get token from cookie", slog.Any("err", err))
		redirectToLogin(w, r, authenticator, r.URL, logger)
		return forwardauth.Token{}, err
	}

	// validate the token
	newToken, err := handler.Validate(r.Context(), token, r)
	switch {
	case errors.Is(err, forwardauth.ErrNotAllowed):
		logger.Debug("access forbidden")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return forwardauth.Token{}, err
	case errors.Is(err, forwardauth.ErrPreviousRefreshTokenExpired),
		errors.Is(err, forwardauth.ErrInvalidRefreshToken),
		errors.Is(err, forwardauth.ErrSessionNotFound):
		// TODO: we're rejecting the token and asking the user to login again. should we delete the session?
		logger.Debug("invalid token received", slog.Any("err", err))
		redirectToLogin(w, r, authenticator, r.URL, logger)
		return forwardauth.Token{}, err
	case err != nil:
		logger.Error("failed to validate token", slog.Any("err", err))
		http.Error(w, "failed to validate token", http.StatusInternalServerError)
		return forwardauth.Token{}, err
	}
	// if the token was updated, resign the token
	if newToken.ID != token.ID {
		logger.Debug("token updated")
		// we know the token can be signed because we created it in handleLogin()
		signedToken, _ := newToken.Sign([]byte(cfg.Key))
		setTokenCookie(w, cfg.CookieName, signedToken, cfg.Domain)
	}

	return newToken, nil
}
