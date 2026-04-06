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
	sessionPrefix = "forward-auth-session"
)

type Session struct {
	LastSeen  time.Time         `json:"last_seen"`
	UserAgent string            `json:"user_agent"`
	UserInfo  provider.UserInfo `json:"user_info"`
}

type Manager struct {
	cache.Cache[Session]
}

func New(ttl time.Duration, cfg configuration.StorageConfiguration) (*Manager, error) {
	store, err := cache.New[Session](ttl, sessionPrefix, cfg)
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	return &Manager{Cache: store}, nil
}

func (m *Manager) Add(ctx context.Context, userInfo provider.UserInfo, userAgent string) (string, error) {
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

func (m *Manager) Middleware(cookieName string, strict bool) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID, session, err := m.validateRequestSession(r, cookieName)
			if err != nil && strict {
				http.Error(w, "failed to validate session", http.StatusUnauthorized)
				return
			}
			if err == nil {
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

func SessionFromCtx(ctx context.Context) (string, Session, bool) {
	s, ok := ctx.Value(sessionCtxKey{}).(sessionInfo)
	return s.sessionID, s.session, ok
}

func ctxWithSession(ctx context.Context, sessionID string, session Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, sessionInfo{sessionID: sessionID, session: session})
}
