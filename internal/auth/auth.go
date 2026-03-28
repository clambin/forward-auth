package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/clambin/forward-auth/internal/auth/authn"
	"github.com/clambin/forward-auth/internal/auth/authz"
	"github.com/clambin/forward-auth/internal/auth/cache"
)

var (
	ErrAuthzFailed = fmt.Errorf("user not authorized to access resource")
)

type authorizer interface {
	Allow(url *url.URL, user string) bool
}

type ForwardAuthServer struct {
	sessionStore  cache.Cache[string]
	states        states
	authenticator authn.Authenticator
	authorizer    authorizer
}

func New(ctx context.Context, configuration Configuration) (*ForwardAuthServer, error) {
	var err error
	var s ForwardAuthServer
	s.sessionStore, err = cache.New[string](configuration.SessionTTL, "forward-auth-session", configuration.Storage)
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	s.states.cache, err = cache.New[string](configuration.StateTTL, "forward-auth-state", configuration.Storage)
	if err != nil {
		return nil, fmt.Errorf("state store: %w", err)
	}
	s.authenticator, err = authn.New(ctx, configuration.Authn)
	if err != nil {
		return nil, fmt.Errorf("authenticator: %w", err)
	}
	s.authorizer, err = authz.New(configuration.Authz)
	if err != nil {
		return nil, fmt.Errorf("authorizer: %w", err)
	}
	return &s, nil
}

func (s *ForwardAuthServer) ValidateSession(ctx context.Context, sessionID string, url *url.URL) (string, error) {
	// authenticate the user: see if we have a session in our store
	user, err := s.sessionStore.Get(ctx, sessionID)
	if err != nil {
		return "", fmt.Errorf("session: %w", err)
	}
	// check if the user is allowed to access the resource
	if !s.authorizer.Allow(url, user) {
		return "", ErrAuthzFailed
	}
	return user, nil
}

func (s *ForwardAuthServer) DeleteSession(ctx context.Context, sessionID string) error {
	return s.sessionStore.Delete(ctx, sessionID)
}

func (s *ForwardAuthServer) InitiateLogin(ctx context.Context, url string) (string, error) {
	// create a state in the state cache
	state, err := s.states.Allocate(ctx, url)
	if err != nil {
		return "", fmt.Errorf("state: %w", err)
	}

	// return the login URL with the state as a query parameter
	return s.authenticator.AuthURL(state), nil
}

func (s *ForwardAuthServer) ConfirmLogin(ctx context.Context, state string, code string) (string, string, string, time.Duration, error) {
	// retrieve the state from the state cache
	u, err := s.states.Validate(ctx, state)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("state: %w", err)
	}
	// use the code to get the user info
	userInfo, err := s.authenticator.GetUserInfo(ctx, code)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("confirm login: %w", err)
	}
	// create a session in the session cache
	sessionID := makeRandomID()
	if err = s.sessionStore.Set(ctx, sessionID, userInfo.Email); err != nil {
		return "", "", "", 0, fmt.Errorf("create session: %w", err)
	}
	return userInfo.Email, sessionID, u, s.sessionStore.TTL(), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type states struct {
	cache cache.Cache[string]
}

func (s *states) Allocate(ctx context.Context, value string) (string, error) {
	state := makeRandomID()
	return state, s.cache.Set(ctx, state, value)
}

func (s *states) Validate(ctx context.Context, state string) (string, error) {
	return s.cache.Get(ctx, state)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func makeRandomID() string {
	const size = 32 // 256 bits
	var b [size]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
