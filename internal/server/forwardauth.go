package server

import (
	"cmp"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/session"
)

const (
	forwardedUserEmailHeader  = "X-Forwarded-User-Email"
	forwardedUserNameHeader   = "X-Forwarded-User-Name"
	forwardedUserGroupsHeader = "X-Forwarded-User-Groups"
)

func handleForwardAuth(
	authorizer Authorizer,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := session.AuthenticatedUser(r)
		if !ok {
			logger.Error("no authenticated user found")
			http.Error(w, "no authenticated user found", http.StatusUnauthorized)
			return
		}

		// is the user authorized to access the resource?
		if !authorizer.Allow(r.URL, identity.Email) {
			logger.Warn("user not authorized to access resource", slog.String("user", identity.Email), slog.String("url", r.URL.String()))
			http.Error(w, "user not authorized to access resource", http.StatusForbidden)
			return
		}

		// user is allowed. set user headers and return OK to the forwardAuth middleware
		setUserHeaders(w, identity, authorizer.GroupsForUser(identity.Email))
		w.WriteHeader(http.StatusOK)
	})
}

// setUserHeaders sets the user headers on the response. Blank headers are not set.
func setUserHeaders(w http.ResponseWriter, identity provider.Identity, groups []string) {
	h := w.Header()
	h.Set(forwardedUserEmailHeader, identity.Email)
	if identity.Name != "" {
		h.Set(forwardedUserNameHeader, identity.Name)
	}
	if len(groups) > 0 {
		slices.Sort(groups)
		w.Header().Set(forwardedUserGroupsHeader, strings.Join(groups, ","))
	}
}

// withForwardAuthMiddleware returns a middleware that restores the original request
// sent in the Traefik forwardAuth request headers.
func withForwardAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			r = r.Clone(r.Context())
			r.Method, r.URL, err = OriginalRequest(r)
			if err != nil {
				http.Error(w, "failed to restore original request", http.StatusBadRequest)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// OriginalRequest restores the original request method and URL from the Traefik forwardAuthrequest headers.
// This allows us to route forwardAuth requests vs. logout requests (/_oauth/logout) to the correct handler.
func OriginalRequest(r *http.Request) (string, *url.URL, error) {
	path := cmp.Or(r.Header.Get("X-Forwarded-Uri"), "/")

	u, err := url.ParseRequestURI(path)
	if err == nil {
		u.Scheme = cmp.Or(r.Header.Get("X-Forwarded-Proto"), "https")
		u.Host = r.Header.Get("X-Forwarded-Host")
	}

	return cmp.Or(r.Header.Get("X-Forwarded-Method"), http.MethodGet), u, err
}
