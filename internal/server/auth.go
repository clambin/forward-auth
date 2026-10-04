package server

import (
	"cmp"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/clambin/forward-auth/internal/token"
)

const (
	forwardedUserEmailHeader  = "X-Forwarded-User-Email"
	forwardedUserNameHeader   = "X-Forwarded-User-Name"
	forwardedUserGroupsHeader = "X-Forwarded-User-Groups"
)

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
		Host:     r.Header.Get("X-Forwarded-Host"),
		Path:     path,
		RawQuery: rawQuery,
	}
}

// setUserHeaders sets the user headers on the response. Blank headers are not set.
func setUserHeaders(w http.ResponseWriter, token *token.Token, groups []string) {
	h := w.Header()
	h.Set(forwardedUserEmailHeader, token.Identity.Email)
	if token.Identity.Name != "" {
		h.Set(forwardedUserNameHeader, token.Identity.Name)
	}
	if len(groups) > 0 {
		slices.Sort(groups)
		w.Header().Set(forwardedUserGroupsHeader, strings.Join(groups, ","))
	}
}

// handleForwardAuth is the main handler for the forward-auth middleware.
// It authenticates the user by extracting the session cookie from the request and validating it against the session store.
// If the session is missing/invalid, the user is redirected to the OIDC login page.
// If the session is valid, the user is authorized and the request is forwarded to the original destination.
//
// TODO: review
func handleForwardAuth(
	cookieName string,
	key []byte,
	tokenManager *token.TokenManager,
	authenticator Authenticator,
	authorizer Authorizer,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// redirect to login page
		// TODO: this ignores the original method. Should we limit this to GET requests?
		redirectToLogin := func(originalURL *url.URL) {
			redirectURL, err := authenticator.InitiateLogin(r.Context(), originalURL.String())
			if err != nil {
				logger.Error("failed to initiate login", "err", err)
				http.Error(w, "failed to initiate login", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		}

		// restore original request
		_, originalURL := originalRequest(r)

		// get the jwt token
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			logger.Error("failed to retrieve cookie", "err", err)
			redirectToLogin(originalURL)
			return
		}
		tok, err := token.ParseToken(cookie.Value, key)
		if err != nil {
			logger.Error("failed to parse cookie", "err", err)
			redirectToLogin(originalURL)
			return
		}

		// validate the token
		if tok, err = tokenManager.Validate(r.Context(), tok); err != nil {
			// token was invalid or expired and not refreshable. Redirect to login
			logger.Error("invalid token in cookie", "err", err, "cookie", cookieName)
			redirectToLogin(originalURL)
			return
		}

		// authorize the request
		if !authorizer.Allow(originalURL, tok.Subject) {
			logger.Warn("forbidden", "url", originalURL, "subject", tok.Subject)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// authorize the request
		setUserHeaders(w, tok, authorizer.GroupsForUser(tok.Subject))
		w.WriteHeader(http.StatusOK)
	})
}

// handleLogin is called by the OICD provider after the user has logged in.
// It registers the session in the session store and redirects the user to the original destination.
// This will trigger another call to forwardAuthHandler, which authenticates the user and authorizes the request.
//
// TODO: review
func handleLogin(
	cookieName string,
	key []byte,
	domain string,
	tokenManager *token.TokenManager,
	authenticator Authenticator,
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

		logger.Debug("received valid login request")

		userInfo, redirectURL, err := authenticator.ConfirmLogin(r.Context(), state, code)
		if err != nil {
			logger.Warn("rejecting login request: failed to validate login", slog.Any("err", err))
			http.Error(w, "failed to validate login", http.StatusUnauthorized)
			return
		}

		ulog := logger.With(slog.String("user", userInfo.Email))
		ulog.Debug("user validated successfully")

		// create a token for the new session
		tok, err := tokenManager.Token(r.Context(), userInfo)
		if err != nil {
			ulog.Warn("failed to create token", slog.Any("err", err))
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		signedToken, err := tok.Sign(key)
		if err != nil {
			ulog.Warn("failed to sign token", slog.Any("err", err))
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:   cookieName,
			Value:  signedToken,
			Domain: domain,
			Path:   "/",
			//Expires:  time.Now().Add(tokenManager.TTL()), // leaving this out so the browser sends an expired cookie
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		ulog.Info("login successful")
	})
}
