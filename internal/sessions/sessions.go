package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/cache"
	"github.com/clambin/forward-auth/internal/configuration"
)

const (
	sessionKeyPrefix = "forward-auth-session"
)

// Session represents a user session.
type Session struct {
	LastSeen  time.Time         `json:"last_seen"`
	UserAgent string            `json:"user_agent"`
	UserInfo  provider.Identity `json:"user_info"`
}

// Manager manages user sessions.
// Most of the methods are implemented by the underlying cache.Cache interface.
type Manager struct {
	cache.Cache[Session]
}

// New create a new session Manager for the given configuration.
// ttl defines when sessions expire.
// cfg defines the storage configuration (i.e., local or Redis).
func New(ttl time.Duration, cfg configuration.StorageConfiguration) (*Manager, error) {
	store, err := cache.New[Session](ttl, sessionKeyPrefix, cfg)
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	return &Manager{Cache: store}, nil
}

// Add creates a new session for the given user info.
func (m *Manager) Add(ctx context.Context, userInfo provider.Identity, userAgent string) (string, error) {
	sessionID := makeRandomSessionID()
	session := Session{
		UserInfo:  userInfo,
		UserAgent: userAgent,
		LastSeen:  time.Now(),
	}
	if err := m.Set(ctx, sessionID, session); err != nil {
		return "", fmt.Errorf("session store: %w", err)
	}
	return sessionID, nil
}

func makeRandomSessionID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Middleware returns a middleware that validates the session cookie in the HTTP request.
// In strict mode, the middleware rejects the request if the session cookie is missing or invalid.
// If the request is allowed, the middleware adds the session (which may be invalid in non-strict mode)
// to the request context and forwards the request to the next handler.
func (m *Manager) Middleware(cookieName string, strict bool) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID, session, err := m.validateRequestSession(r, cookieName)
			if err != nil && strict {
				http.Error(w, "failed to validate session", http.StatusUnauthorized)
				return
			}
			if err == nil {
				// update the session's lastSeen and userAgent fields without affecting expiration.
				session.LastSeen = time.Now()
				session.UserAgent = r.UserAgent()
				if err = m.Update(r.Context(), sessionID, session); err != nil {
					http.Error(w, "failed to update session", http.StatusInternalServerError)
					return
				}
				r = r.Clone(ctxWithSession(r.Context(), sessionID, session))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Manager) validateRequestSession(r *http.Request, cookieName string) (string, Session, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", Session{}, err
	}
	session, err := m.Get(r.Context(), cookie.Value)
	if err != nil {
		return "", Session{}, err
	}
	return cookie.Value, session, nil
}

type sessionCtxKey struct{}

type sessionInfo struct {
	sessionID string
	session   Session
}

// SessionFromCtx returns the session ID and session data from the request context, if present.
// Otherwise, the third return value is false.
func SessionFromCtx(ctx context.Context) (string, Session, bool) {
	s, ok := ctx.Value(sessionCtxKey{}).(sessionInfo)
	return s.sessionID, s.session, ok
}

// ctxWithSession returns a new context with the given session ID and session data.
func ctxWithSession(ctx context.Context, sessionID string, session Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, sessionInfo{sessionID: sessionID, session: session})
}
