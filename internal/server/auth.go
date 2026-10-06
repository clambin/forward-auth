package server

import (
	"cmp"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"uuid"

	"github.com/clambin/forward-auth/internal/token"
)

const (
	forwardedUserEmailHeader  = "X-Forwarded-User-Email"
	forwardedUserNameHeader   = "X-Forwarded-User-Name"
	forwardedUserGroupsHeader = "X-Forwarded-User-Groups"
)

// handleForwardAuth is the main handler for the forward-auth middleware.
// It authenticates the user by validating the JWT token in the session cookie:
// - If the token has expired, the token manager attempts to refresh the token.
// - If the token is invalid, or could not be refreshed, the user is redirected to the OIDC login page to create a new session.
// Once the user is authenticated, the request is authorized and the request is forwarded to the original destination.
func handleForwardAuth(
	cookieName string,
	key []byte,
	domain string,
	tokenManager *token.Manager,
	authenticator Authenticator,
	authorizer Authorizer,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// restore original request
		originalMethod, originalURL := originalRequest(r)

		// request logger
		reqLogger := logger.With(
			slog.String("reqID", uuid.New().String()),
			slog.Group("request",
				slog.String("method", originalMethod),
				slog.String("url", originalURL.String()),
			),
		)

		// redirect to login page
		redirectToLogin := func(originalURL *url.URL) {
			redirectURL, err := authenticator.InitiateLogin(r.Context(), originalURL.String())
			if err != nil {
				reqLogger.Error("failed to initiate login", slog.Any("err", err))
				http.Error(w, "failed to initiate login", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		}

		// get the jwt token
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			reqLogger.Error("failed to retrieve cookie", slog.Any("err", err))
			redirectToLogin(originalURL)
			return
		}
		signedToken := cookie.Value
		tok, err := token.ParseToken(signedToken, key)
		if err != nil {
			reqLogger.Error("failed to parse cookie", slog.Any("err", err))
			redirectToLogin(originalURL)
			return
		}

		// TODO: remove this when done.
		reqLogger.Debug("parsed token", slog.Any("token", tok))
		currentRefreshToken := tok.RefreshToken

		// validate the token
		if tok, err = tokenManager.Validate(r.Context(), tok, reqLogger); err != nil {
			// token was invalid or expired and not refreshable. Redirect to login
			reqLogger.Error("invalid token in cookie", slog.Any("err", err), slog.String("cookie", cookieName))
			redirectToLogin(originalURL)
			return
		}

		// if the token has changed, update it in the response's cookie and redirect so the browser tries again.
		if tok.RefreshToken != currentRefreshToken {
			signedToken, err = tok.Sign(key)
			if err != nil {
				reqLogger.Error("failed to sign token", slog.Any("err", err))
				http.Error(w, "failed to sign token", http.StatusInternalServerError)
				return
			}
			setTokenCookie(w, cookieName, signedToken, domain)
			http.Redirect(w, r, originalURL.String(), http.StatusSeeOther)
			return
		}

		// is the request authorized?
		if !authorizer.Allow(originalURL, tok.Identity.Email) {
			reqLogger.Warn("request forbidden by authorizer", slog.Any("id", tok.Identity))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// the request is authorized
		setUserHeaders(w, tok, authorizer.GroupsForUser(tok.Identity.Email))
		w.WriteHeader(http.StatusOK)
	})
}

// handleLogin is called by the OICD provider after the user has logged in.
// It establishes a session through a JWT token and redirects the user to the original destination.
// This will trigger another call to forwardAuthHandler, which authenticates the user and authorizes the request.
func handleLogin(
	cookieName string,
	key []byte,
	domain string,
	tokenManager *token.Manager,
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
			ulog.Error("failed to create token", slog.Any("err", err))
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		signedToken, err := tok.Sign(key)
		if err != nil {
			ulog.Error("failed to sign token", slog.Any("err", err))
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		setTokenCookie(w, cookieName, signedToken, domain)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		ulog.Info("login successful")
	})
}

// setTokenCookie adds a signed token cookie on the response.
func setTokenCookie(w http.ResponseWriter, cookieName, signedToken, domain string) {
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
