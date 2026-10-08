package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"codeberg.org/clambin/go-common/cache"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// A Session represents a user session on the server.
type Session struct {
	IssuedAt         time.Time         `json:"issuedAt"`
	LastSeen         time.Time         `json:"lastSeen"`
	Identity         provider.Identity `json:"identity"`
	ID               string            `json:"id"`
	UserAgent        string            `json:"userAgent"`
	RefreshTokenHash refreshTokenHash  `json:"refreshTokenHash"`
}

// A Manager validates the session ID from the http request's session JWT against its data store.
// The session is refreshed each time the session JWT expires.  At this point, we generate a new refresh token.
type Manager struct {
	Store Store
}

func New(ttl time.Duration, cfg configuration.StorageConfiguration) (*Manager, error) {
	var store Store
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
		store = &RedisStore{Client: redisClient}
	default:
		return nil, fmt.Errorf("unknown store type: %s", cfg.Type)
	}
	return &Manager{Store: store}, nil
}

// CreateSession creates a new session and returns a JWT token to be sent back to the client.
func (m *Manager) CreateSession(ctx context.Context, id provider.Identity, r *http.Request) (Token, error) {
	// create the session token, to be sent back to the client
	token := generateToken(id)
	// store a session in the data store
	session := Session{
		ID:               token.ID,
		Identity:         id,
		RefreshTokenHash: token.RefreshToken.hash(),
		IssuedAt:         time.Now(),
		UserAgent:        r.Header.Get("User-Agent"),
	}
	if err := m.Store.Put(ctx, m.key(token), session); err != nil {
		return token, err
	}
	return token, nil
}

// Validate validates that the session in the token exists in the store.  If found, Validate() updates
// the user agent and the last refresh time in the store. It returns the updated token.
func (m *Manager) Validate(ctx context.Context, token Token, r *http.Request) (Token, error) {
	// if the session doesn't exist, it's an error
	session, err := m.Store.Get(ctx, m.key(token))
	if err != nil {
		return token, err
	}

	// check that the refresh token matches the stored hash
	if session.RefreshTokenHash != token.RefreshToken.hash() {
		return token, ErrInvalidRefreshToken
	}

	// update the user agent, last refresh time in the store
	session.UserAgent = r.Header.Get("User-Agent")
	session.LastSeen = time.Now()
	err = m.Store.Put(ctx, m.key(token), session)
	if err != nil {
		return token, err
	}

	// refresh the token
	token.ExpiresAt.Time = time.Now().Add(tokenExpiration)
	return token, nil
}

func (m *Manager) key(token Token) string {
	return strings.Join([]string{
		"session",
		token.Identity.Email,
		token.SessionID,
	}, ":")
}

// Store abstracts the storage of session data.
// Currently implemented with an in-memory cache and a Redis store.
type Store interface {
	Put(ctx context.Context, key string, session Session) error
	Get(ctx context.Context, key string) (Session, error)
	Len(ctx context.Context) (int, error)
}

var (
	_ Store = (*InMemoryStore)(nil)
	_ Store = (*RedisStore)(nil)
)

type InMemoryStore struct {
	Cache *cache.Cache[string, Session]
}

func (s InMemoryStore) Put(_ context.Context, key string, session Session) error {
	s.Cache.Add(key, session)
	return nil
}

func (s InMemoryStore) Get(_ context.Context, key string) (Session, error) {
	if session, ok := s.Cache.Get(key); ok {
		return session, nil
	}
	return Session{}, ErrSessionNotFound
}

func (s InMemoryStore) Len(_ context.Context) (int, error) {
	return s.Cache.Len(), nil
}

type RedisStore struct {
	Client *redis.Client
	TTL    time.Duration
}

func (s RedisStore) Put(ctx context.Context, key string, session Session) error {
	rawSession, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	return s.Client.Set(ctx, key, rawSession, s.TTL).Err()

}

func (s RedisStore) Get(ctx context.Context, key string) (Session, error) {
	rawSession, err := s.Client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrSessionNotFound
	}
	var session Session
	err = json.Unmarshal([]byte(rawSession), &session)
	if err != nil {
		return Session{}, fmt.Errorf("json: %w", err)
	}
	return session, nil
}

func (s RedisStore) Len(ctx context.Context) (int, error) {
	i := s.Client.Scan(ctx, 0, "session:*", 100).Iterator()
	var found int
	for i.Next(ctx) {
		found++
	}
	return found, i.Err()
}

var _ prometheus.Collector = &InstrumentedSessionManager{}

type InstrumentedSessionManager struct {
	SessionMgr *Manager
	Desc       *prometheus.Desc
}

func (m InstrumentedSessionManager) Describe(descs chan<- *prometheus.Desc) {
	descs <- m.Desc
}

func (m InstrumentedSessionManager) Collect(metrics chan<- prometheus.Metric) {
	count, err := m.SessionMgr.Store.Len(context.Background())
	if err == nil {
		metrics <- prometheus.MustNewConstMetric(m.Desc, prometheus.GaugeValue, float64(count))
	}
}
