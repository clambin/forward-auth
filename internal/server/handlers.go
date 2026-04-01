package server

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/internal/authn/cache"
)

const (
	xForwardedUser = "X-Forwarded-User"
)

// forwardAuthHandler is the main handler for the forward-auth middleware.
// It authenticates the user by extracting the session cookie from the request and validating it against the session store.
// If the session is missing/invalid, the user is redirected to the OIDC login page.
// If the session is valid, the user is authorized and the request is forwarded to the original destination.
func forwardAuthHandler(
	cookieName string,
	authenticator Authenticator,
	authorizer Authorizer,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := logger.With(slog.String("url", r.URL.String()))

		// get the session cookie
		sessionCookie, err := r.Cookie(cookieName)
		if err != nil {
			l.Warn("rejecting request: no session cookie found", slog.Any("err", err))
			redirectToLoginPage(w, r, authenticator, logger)
			return
		}

		// authenticate the user: check if the cookie is in our Sessions Store
		session, err := authenticator.Validate(r.Context(), sessionCookie.Value)

		// no valid session cookie found: redirect to login page
		if errors.Is(err, cache.ErrNotFound) {
			l.Warn("rejecting request: no valid session found", slog.Any("err", err))
			redirectToLoginPage(w, r, authenticator, logger)
			return
		}

		if err != nil {
			logger.Warn("rejecting request: failed to validate session", slog.Any("err", err))
			http.Error(w, "failed to validate session", http.StatusInternalServerError)
			return
		}

		if !authorizer.Allow(r.URL, session.UserInfo.Email) {
			logger.Warn("rejecting request: user is not authorized to access the requested resource")
			http.Error(w, "user is not authorized to access the requested resource", http.StatusForbidden)
			return
		}

		// valid session cookie found, request authorized: accept the request
		w.Header().Set(xForwardedUser, session.UserInfo.Email)
		w.WriteHeader(http.StatusOK)
	})
}

func redirectToLoginPage(w http.ResponseWriter, r *http.Request, authenticator Authenticator, logger *slog.Logger) {
	redirectURL, err := authenticator.InitiateLogin(r.Context(), r.URL.String())
	if err != nil {
		logger.Warn("rejecting request: failed to redirect to login page", slog.Any("err", err))
		http.Error(w, "failed to redirect to login page", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// logoutHandler logs out the user: it removes the session from the session store and sends an empty Cookie to the user.
// This means that the user's next request has an invalid cookie, triggering a new oauth flow.
func logoutHandler(
	cookieName string,
	domain string,
	authenticator Authenticator,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get the session cookie
		sessionCookie, err := r.Cookie(cookieName)
		if err != nil {
			redirectToLoginPage(w, r, authenticator, logger)
			return
		}

		// authenticate the user: check if the cookie is in our Sessions Store
		user, err := authenticator.Validate(r.Context(), sessionCookie.Value)

		// if we don't have a valid session, return an error
		if err != nil {
			logger.Warn("rejecting logout request: no valid session cookie found", "err", err)
			http.Error(w, "no valid session cookie found", http.StatusUnauthorized)
			return
		}

		// remove the session
		if err = authenticator.Close(r.Context(), sessionCookie.Value); err != nil {
			logger.Warn("rejecting logout request: failed to delete session", "err", err)
			http.Error(w, "failed to delete session", http.StatusInternalServerError)
			return
		}

		// clear the session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Domain:   domain,
			Path:     "/",
			Expires:  time.Now().Add(-time.Hour),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		logger.Info("logout successful", "user", user)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("user logged out"))
	})
}

// loginHandler is called by the OICD provider after the user has logged in.
// It registers the session in the session store and redirects the user to the original destination.
// This will trigger another call to forwardAuthHandler, which authenticates the user and authorizes the request.
func loginHandler(
	cookieName string,
	domain string,
	authenticator Authenticator,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			logger.Warn("rejecting login request: missing state or code")
			http.Error(w, "missing state or code", http.StatusBadRequest)
			return
		}

		session, sessionID, redirectURL, ttl, err := authenticator.ConfirmLogin(r.Context(), state, code)
		if err != nil {
			logger.Warn("rejecting login request: failed to validate login", "err", err)
			http.Error(w, "failed to validate login", http.StatusUnauthorized)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    sessionID,
			Domain:   domain,
			Path:     "/",
			Expires:  time.Now().Add(ttl),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		logger.Info("login successful", "user", session.UserInfo.Email)
	})
}

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
