// Package forwardauth implements the forwardAuth functionality.
package forwardauth

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/clambin/forward-auth/internal/configuration"
)

type Result int

const (
	Error Result = iota
	Allowed
	NotAuthenticated
	Forbidden
)

type Authorizer interface {
	Allow(url *url.URL, user string) bool
	GroupsForUser(email string) []string
}

// Handler implements the forwardAuth functionality.
type Handler struct {
	Sessions
	Authorizer
}

func New(ttl time.Duration, authorizer Authorizer, cfg configuration.StorageConfiguration) (*Handler, error) {
	var h *Handler
	sessions, err := newSessions(ttl, cfg)
	if err == nil {
		h = &Handler{Sessions: sessions, Authorizer: authorizer}
	}
	return h, err
}

// Validate evaluates whether the user is allowed to access the requested URL.
// It returns a Result indicating whether the user is allowed to access the requested URL,
// and a session.Token, which may have been updated. Check the token's ID to verify whether the session was updated.
func (h *Handler) Validate(ctx context.Context, token Token, r *http.Request) (Result, Token, error) {
	// validate the session (i.e., authenticate the user)
	newToken, err := h.Sessions.Validate(ctx, token, r)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrInvalidRefreshToken) {
			return NotAuthenticated, Token{}, nil
		}
		return Error, token, err
	}
	// authorize the request
	_, requestURL := OriginalRequest(r)
	if !h.Allow(requestURL, newToken.Identity.Email) {
		return Forbidden, newToken, nil
	}
	return Allowed, newToken, nil
}

// OriginalRequest restores the original request method and URL from the Traefik forwardAuthrequest headers.
// This allows us to route forwardAuth requests vs. logout requests (/_oauth/logout) to the correct handler.
func OriginalRequest(r *http.Request) (string, *url.URL) {
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
