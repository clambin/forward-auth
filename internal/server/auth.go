package server

import (
	"cmp"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clambin/forward-auth/internal/sessions"
)

const (
	forwardedUserHeader = "X-Forwarded-User"
)

// forwardAuthHandler is the main handler for the forward-auth middleware.
// It authenticates the user by extracting the session cookie from the request and validating it against the session store.
// If the session is missing/invalid, the user is redirected to the OIDC login page.
// If the session is valid, the user is authorized and the request is forwarded to the original destination.
func forwardAuthHandler(
	authenticator Authenticator,
	authorizer Authorizer,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// restore the original request method and URL
		_, u := originalRequest(r)

		l := logger.With(slog.String("url", u.String()))

		// get the session added by the session validator middleware
		_, session, ok := sessions.SessionFromCtx(r.Context())

		// no valid session cookie found: redirect to login page
		if !ok {
			l.Warn("rejecting request: no valid session found")
			redirectToLoginPage(w, r, authenticator, logger)
			return
		}

		// session is valid. check if the user is authorized to access the requested resource
		if !authorizer.Allow(u, session.UserInfo.Email) {
			l.Warn("rejecting request: user is not authorized to access the requested resource")
			http.Error(w, "user is not authorized to access the requested resource", http.StatusForbidden)
			return
		}

		// valid session cookie found, request authorized: accept the request
		w.Header().Set(forwardedUserHeader, session.UserInfo.Email)
		w.WriteHeader(http.StatusOK)
	})
}

// originalRequest restores the original request method and URL from the Traefik forwardAuthrequest headers.
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

func redirectToLoginPage(w http.ResponseWriter, r *http.Request, authenticator Authenticator, logger *slog.Logger) {
	redirectURL, err := authenticator.InitiateLogin(r.Context(), r.URL.String())
	if err != nil {
		logger.Warn("rejecting request: failed to redirect to login page", slog.Any("err", err))
		http.Error(w, "failed to redirect to login page", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// loginHandler is called by the OICD provider after the user has logged in.
// It registers the session in the session store and redirects the user to the original destination.
// This will trigger another call to forwardAuthHandler, which authenticates the user and authorizes the request.
func loginHandler(
	cookieName string,
	domain string,
	authenticator Authenticator,
	mgr SessionManager,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// use state & code to validate the login and retrieve the user info
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			logger.Warn("rejecting login request: missing state or code")
			http.Error(w, "missing state or code", http.StatusBadRequest)
			return
		}

		userInfo, redirectURL, err := authenticator.ConfirmLogin(r.Context(), state, code)
		if err != nil {
			logger.Warn("rejecting login request: failed to validate login", "err", err)
			http.Error(w, "failed to validate login", http.StatusUnauthorized)
			return
		}

		// create a session in the session cache
		sessionID, err := mgr.Add(r.Context(), userInfo, r.UserAgent())
		if err != nil {
			logger.Warn("rejecting login request: failed to create session", "err", err)
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    sessionID,
			Domain:   domain,
			Path:     "/",
			Expires:  time.Now().Add(mgr.TTL()),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		logger.Info("login successful", "user", userInfo.Email)
	})
}
