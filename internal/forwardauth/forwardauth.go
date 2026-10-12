package forwardauth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"codeberg.org/clambin/go-common/cache"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/redis/go-redis/v9"
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
	var store store
	switch cfg.Type {
	case "local", "":
		store = &InMemoryStore{Cache: cache.New[string, Session](ttl, time.Minute)}
	case "redis":
		redisClient := redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Addr,
			Username: cfg.Redis.Username,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})
		store = &RedisStore{Client: redisClient, TTL: ttl}
	default:
		return nil, fmt.Errorf("unknown store type: %s", cfg.Type)
	}
	return &Handler{store: store, Authorizer: authorizer}, nil
}

// Validate evaluates whether the user is allowed to access the requested URL.
// It returns a Result indicating whether the user is allowed to access the requested URL,
// and a session.Token, which may have been updated. Check the token's ID to verify whether the session was updated.
func (h *Handler) Validate(ctx context.Context, token Token, r *http.Request) (Result, Token, error) {
	// validate the session (i.e., authenticate the user)
	newToken, err := h.Sessions.Validate(ctx, token, r)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return NotAuthenticated, Token{}, nil
		}
		return Error, token, err
	}
	// authorize the request
	if !h.Allow(originalRequestURL(r), newToken.Identity.Email) {
		return Forbidden, token, nil
	}
	return Allowed, newToken, nil
}

// originalRequestURL restores the original request method and URL from the Traefik forwardAuthrequest headers.
// This allows us to route forwardAuth requests vs. logout requests (/_oauth/logout) to the correct handler.
func originalRequestURL(r *http.Request) *url.URL {
	path := cmp.Or(r.Header.Get("X-Forwarded-Uri"), "/")
	var rawQuery string
	if n := strings.Index(path, "?"); n > 0 {
		rawQuery = path[n+1:]
		path = path[:n]
	}

	return &url.URL{
		Scheme:   cmp.Or(r.Header.Get("X-Forwarded-Proto"), "https"),
		Host:     r.Header.Get("X-Forwarded-Host"),
		Path:     path,
		RawQuery: rawQuery,
	}
}
