package server

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/internal/auth"
)

// forwardAuthHandler is the main handler for the forward-auth middleware.
// It authenticates the user by extracting the session cookie from the request and validating it against the session store.
// If the session is missing/invalid, the user is redirected to the OIDC login page.
// If the session is valid, the user is authorized and the request is forwarded to the original destination.
func forwardAuthHandler(
	cookieName string,
	forwardAuth ForwardAuth,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get the session cookie
		sessionCookie, err := r.Cookie(cookieName)
		if err != nil {
			redirectToLoginPage(w, r, forwardAuth, logger)
			return
		}

		// authenticate the user: check if the cookie is in our Sessions Store
		user, err := forwardAuth.ValidateSession(r.Context(), sessionCookie.Value, r.URL)
		switch {
		case err == nil:
			// valid session cookie found: accept the request
			w.Header().Set("X-Forwarded-User", user.Email)
			w.WriteHeader(http.StatusOK)
		case errors.Is(err, auth.ErrNoSession):
			// no session cookie found: redirect to login page
			redirectToLoginPage(w, r, forwardAuth, logger)
		case errors.Is(err, auth.ErrNotAuthorized):
			// user is not authorized: reject the request
			logger.Warn("rejecting request: user is not authorized", "err", err)
			http.Error(w, "user is not authorized", http.StatusForbidden)
		default:
			logger.Warn("rejecting request: failed to validate session", "err", err)
			http.Error(w, "failed to validate session", http.StatusInternalServerError)
		}
	})
}

func redirectToLoginPage(w http.ResponseWriter, r *http.Request, forwardAuth ForwardAuth, logger *slog.Logger) {
	redirectURL, err := forwardAuth.InitiateLogin(r.Context(), r.URL.String())
	if err != nil {
		logger.Warn("rejecting request: failed to redirect to login page", "err", err)
		http.Error(w, "failed to redirect to login page", http.StatusInternalServerError)
		return
	}
	logger.Warn("rejecting request: no valid session cookie found", "err", err)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// logoutHandler logs out the user: it removes the session from the session store and sends an empty Cookie to the user.
// This means that the user's next request has an invalid cookie, triggering a new oauth flow.
func logoutHandler(
	cookieName string,
	domain string,
	forwardAuth ForwardAuth,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get the session cookie
		sessionCookie, err := r.Cookie(cookieName)
		if err != nil {
			redirectToLoginPage(w, r, forwardAuth, logger)
			return
		}

		// authenticate the user: check if the cookie is in our Sessions Store
		user, err := forwardAuth.ValidateSession(r.Context(), sessionCookie.Value, r.URL)

		// if we don't have a valid session, return an error
		if err != nil {
			logger.Warn("rejecting logout request: no valid session cookie found", "err", err)
			http.Error(w, "no valid session cookie found", http.StatusUnauthorized)
			return
		}

		// remove the session
		if err = forwardAuth.DeleteSession(r.Context(), sessionCookie.Value); err != nil {
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
	forwardAuth ForwardAuth,
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

		user, sessionID, redirectURL, ttl, err := forwardAuth.ConfirmLogin(r.Context(), state, code)
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
		})
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)

		logger.Info("login successful", "user", user)
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
