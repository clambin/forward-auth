// Package forwardauth contains the main signatures to implement the forward-auth services
package forwardauth

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/sessions"
)

type SessionManager interface {
	Middleware(cookieName string, strict bool) func(http.Handler) http.Handler
	Get(ctx context.Context, id string) (sessions.Session, error)
	Add(ctx context.Context, userInfo provider.UserInfo, userAgent string) (string, error)
	Delete(ctx context.Context, id string) error
	TTL() time.Duration
	List(ctx context.Context) (map[string]sessions.Session, error)
}

var _ SessionManager = (*sessions.Manager)(nil)

type Authenticator interface {
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state, code string) (provider.UserInfo, string, error)
}

var _ Authenticator = (*authn.Authenticator)(nil)

type Authorizer interface {
	Allow(url *url.URL, user string) bool
}

var _ Authorizer = (*authz.Authorizer)(nil)
