package sessions

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/http"
	"sync"
	"time"
	"uuid"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/cache"
	"github.com/clambin/forward-auth/internal/configuration"
)

const (
	sessionKeyPrefix = "forward-auth-session"
	updateInterval   = time.Minute
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
	sessionUpdateRequests
}

// New create a new session Manager for the given configuration.
// ttl defines when sessions expire.
// cfg defines the storage configuration (i.e., local or Redis).
func New(ttl time.Duration, cfg configuration.StorageConfiguration) (*Manager, error) {
	store, err := cache.New[Session](ttl, sessionKeyPrefix, cfg)
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	m := Manager{
		Cache:    store,
		requests: make(map[string]Session),
	}
	return &m, nil
}

// Run is a background task for the Manager.  It updates the session on a regular interval.
// This prevents a cache write operation for every authenticated request.
func (m *Manager) Run(ctx context.Context) error {
	updateTicker := time.NewTicker(updateInterval)
	defer updateTicker.Stop()

	for {
		select {
		case <-updateTicker.C:
			// write all queued updates to the cache
			for sessionID, session := range m.pending() {
				if err := m.Update(ctx, sessionID, session); err != nil {
					return fmt.Errorf("session store: %w", err)
				}
				m.del(sessionID)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// Add creates a new session for the given user info.
func (m *Manager) Add(ctx context.Context, userInfo provider.Identity, userAgent string) (uuid.UUID, error) {
	sessionID := uuid.NewV4()
	session := Session{
		UserInfo:  userInfo,
		UserAgent: userAgent,
		LastSeen:  time.Now(),
	}
	if err := m.Set(ctx, sessionID.String(), session); err != nil {
		return uuid.UUID{}, fmt.Errorf("session store: %w", err)
	}
	return sessionID, nil
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
				// update the session's lastSeen and userAgent fields
				session.LastSeen = time.Now()
				session.UserAgent = r.UserAgent()
				// queue the update request
				m.add(sessionID, session)

				// add the session to the request context
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

type sessionUpdateRequests struct {
	requests map[string]Session
	mu       sync.Mutex
}

func (s *sessionUpdateRequests) add(sessionID string, session Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[sessionID] = session
}

func (s *sessionUpdateRequests) del(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.requests, sessionID)
}

func (s *sessionUpdateRequests) pending() iter.Seq2[string, Session] {
	// get all pending requests. use a copy so we don't lock the map while we're performing the updates
	s.mu.Lock()
	requests := maps.Clone(s.requests)
	s.mu.Unlock()
	return func(yield func(string, Session) bool) {
		for sessionID, session := range requests {
			if !yield(sessionID, session) {
				return
			}
		}
	}
}
