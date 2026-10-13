// Package forwardauth implements the forwardAuth functionality.
package forwardauth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/clambin/forward-auth/internal/configuration"
)

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrNotAllowed          = errors.New("user is not allowed to access the requested resource")
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
// The request is allowed if the user is authenticated and authorized to access the requested URL.
// and a session.Token, which may have been updated. Check the token's ID to verify whether the session was updated.
func (h *Handler) Validate(ctx context.Context, token Token, r *http.Request) (Token, error) {
	// validate the session (i.e., authenticate the user)
	newToken, err := h.validateToken(ctx, token, r)
	if err != nil {
		return token, err
	}
	// authorize the request
	_, requestURL, err := OriginalRequest(r)
	if err != nil {
		return newToken, fmt.Errorf("failed to parse requested URL: %w", err)
	}
	if !h.Allow(requestURL, newToken.Identity.Email) {
		return newToken, ErrNotAllowed
	}
	return newToken, nil
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
