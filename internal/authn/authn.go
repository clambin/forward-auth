package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/clambin/forward-auth/internal/authn/cache"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
)

const (
	redisSessionKeyPrefix = "forward-auth-session"
	redisStateKeyPrefix   = "forward-auth-state"
)

type Session struct {
	LastSeen time.Time         `json:"last_seen"`
	UserInfo provider.UserInfo `json:"user_info"`
}

// Authenticator authenticates users and manages user sessions.
type Authenticator struct {
	sessions cache.Cache[Session]
	states   states
	provider provider.Provider
}

// New creates a new Authenticator.
func New(ctx context.Context, configuration configuration.AuthnConfiguration) (*Authenticator, error) {
	var err error
	var mgr Authenticator
	mgr.sessions, err = cache.New[Session](configuration.SessionTTL, redisSessionKeyPrefix, configuration.Storage)
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	mgr.states.cache, err = cache.New[string](configuration.StateTTL, redisStateKeyPrefix, configuration.Storage)
	if err != nil {
		return nil, fmt.Errorf("state store: %w", err)
	}
	mgr.provider, err = provider.New(ctx, configuration.Provider)
	if err != nil {
		return nil, fmt.Errorf("authenticator: %w", err)
	}
	return &mgr, nil
}

// Validate checks if the session is valid.
func (m *Authenticator) Validate(ctx context.Context, sessionID string) (*Session, error) {
	// authenticate the user: see if we have a session in our store
	session, err := m.sessions.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	// mark the session as being used
	session.LastSeen = time.Now()
	if err = m.sessions.Update(ctx, sessionID, session); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	return &session, nil
}

// Close deletes a session from the session store.
func (m *Authenticator) Close(ctx context.Context, sessionID string) error {
	return m.sessions.Delete(ctx, sessionID)
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
func (m *Authenticator) ConfirmLogin(ctx context.Context, state string, code string) (*Session, string, string, time.Duration, error) {
	// retrieve the state from the state cache
	u, err := m.states.Validate(ctx, state)
	if err != nil {
		return nil, "", "", 0, fmt.Errorf("state: %w", err)
	}
	// use the code to get the user info
	userInfo, err := m.provider.GetUserInfo(ctx, code)
	if err != nil {
		return nil, "", "", 0, fmt.Errorf("confirm login: %w", err)
	}
	// create a session in the session cache
	sessionID := makeRandomID()
	session := Session{
		UserInfo: userInfo,
		LastSeen: time.Now(),
	}
	if err = m.sessions.Set(ctx, sessionID, session); err != nil {
		return nil, "", "", 0, fmt.Errorf("create session: %w", err)
	}
	return &session, sessionID, u, m.sessions.TTL(), nil
}

// Sessions returns the session cache.
// TODO: code smell. better solution?
func (m *Authenticator) Sessions() cache.Cache[Session] {
	return m.sessions
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
