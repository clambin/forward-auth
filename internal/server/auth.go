package server

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/clambin/forward-auth/internal/forwardauth"
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
	handler *forwardauth.Handler,
	authenticator Authenticator,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// restore original request
		originalMethod, originalURL, err := forwardauth.OriginalRequest(r)
		if err != nil {
			logger.Error("failed to restore original request", slog.Any("err", err))
			http.Error(w, "failed to restore original request", http.StatusInternalServerError)
			return
		}

		// request logger
		reqLogger := logger.With(
			//slog.String("reqID", uuid.New().String()),
			slog.Group("request",
				slog.String("method", originalMethod),
				slog.String("url", originalURL.String()),
			),
		)

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
			reqLogger.Debug("no token in cookie. redirecting to login page")
			redirectToLogin(originalURL)
			return
		}
		signedToken := cookie.Value
		token, err := forwardauth.ParseToken(signedToken, key)
		if err != nil {
			reqLogger.Error("invalid token in cookie. redirecting to login page", slog.Any("err", err))
			redirectToLogin(originalURL)
			return
		}

		newToken, err := handler.Validate(r.Context(), token, r)
		switch {
		case errors.Is(err, forwardauth.ErrNotAllowed):
			reqLogger.Debug("access forbidden")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		case errors.Is(err, forwardauth.ErrInvalidRefreshToken):
			reqLogger.Debug("invalid token. redirecting to login page")
			redirectToLogin(originalURL)
			return
		case errors.Is(err, forwardauth.ErrSessionNotFound):
			reqLogger.Debug("session not found. redirecting to login page")
			redirectToLogin(originalURL)
			return
		case err != nil:
			reqLogger.Error("failed to validate token", slog.Any("err", err))
			http.Error(w, "failed to validate token", http.StatusInternalServerError)
			return
		}
		// if the token was updated, resign the token
		if newToken.ID != token.ID {
			reqLogger.Debug("token updated. resigning token")
			// we know the token can be signed because we created it in handleLogin()
			signedToken, _ = newToken.Sign(key)
			setTokenCookie(w, cookieName, signedToken, domain)
		}

		setUserHeaders(w, token, handler.GroupsForUser(token.Identity.Email))
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
	handler *forwardauth.Handler,
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
		tok, err := handler.CreateSession(r.Context(), userInfo, r)
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

// setUserHeaders sets the user headers on the response. Blank headers are not set.
func setUserHeaders(w http.ResponseWriter, token forwardauth.Token, groups []string) {
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
