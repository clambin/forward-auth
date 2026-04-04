package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/cache"
	"github.com/clambin/forward-auth/internal/configuration"
)

const (
	redisSessionKeyPrefix = "forward-auth-session"
	redisStateKeyPrefix   = "forward-auth-state"
)

// Authenticator authenticates users and manages user sessions.
type Authenticator struct {
	states   states
	provider provider.Provider
}

// New creates a new Authenticator.
func New(ctx context.Context, configuration configuration.Configuration) (*Authenticator, error) {
	var err error
	var mgr Authenticator
	mgr.states.cache, err = cache.New[string](configuration.Authn.StateTTL, redisStateKeyPrefix, configuration.Storage)
	if err != nil {
		return nil, fmt.Errorf("state store: %w", err)
	}
	mgr.provider, err = provider.New(ctx, configuration.Authn.Provider)
	if err != nil {
		return nil, fmt.Errorf("authenticator: %w", err)
	}
	return &mgr, nil
}

// InitiateLogin returns the login URL for the configured OIDC provider.
// To protect against CSRF attacks, the login URL includes a random state parameter, which is
// verified in the [Authenticator.ConfirmLogin] callback.
func (m *Authenticator) InitiateLogin(ctx context.Context, url string) (string, error) {
	// create a state in the state cache
	state, err := m.states.Allocate(ctx, url)
	if err != nil {
		return "", fmt.Errorf("state: %w", err)
	}

	// return the login URL with the state as a query parameter
	return m.provider.AuthURL(state), nil
}

// ConfirmLogin is called by the OIDC provider.  It verifies the state parameter to protect against CSRF attacks,
// uses the code to get the user info, and creates a session in the session cache.
func (m *Authenticator) ConfirmLogin(ctx context.Context, state string, code string) (provider.UserInfo, string, error) {
	// retrieve the state from the state cache
	u, err := m.states.Validate(ctx, state)
	if err != nil {
		return provider.UserInfo{}, "", fmt.Errorf("state: %w", err)
	}
	// use the code to get the user info
	userInfo, err := m.provider.GetUserInfo(ctx, code)
	if err != nil {
		return provider.UserInfo{}, "", fmt.Errorf("confirm login: %w", err)
	}
	return userInfo, u, nil
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
