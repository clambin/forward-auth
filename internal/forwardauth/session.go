package forwardauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"uuid"

	"codeberg.org/clambin/go-common/cache"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

const (
	namespaceKeyPrefix = "forward-auth"
	subsystemKeyPrefix = "session"
)

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

// A Session represents a user session on the server.
type Session struct {
	IssuedAt                 time.Time         `json:"issuedAt"`
	RotatedAt                time.Time         `json:"rotatedAt"`
	Identity                 provider.Identity `json:"identity"`
	ID                       string            `json:"id"`
	UserAgent                string            `json:"userAgent"`
	RefreshSecret            []byte            `json:"refreshSecret"`
	RefreshTokenHash         refreshTokenHash  `json:"refreshTokenHash"`
	PreviousRefreshTokenHash refreshTokenHash  `json:"previousRefreshTokenHash"`
}

// Sessions validates the session ID from the http request's session JWT against its data store.
// The session is refreshed each time the session JWT expires.  At this point, we generate a new refresh token.
// The previous refresh token is still accepted for a short grace period after rotation, so concurrent requests carrying the same
// expired JWT can all renew it.
type Sessions struct {
	store
}

func newSessions(ttl time.Duration, cfg configuration.StorageConfiguration) (Sessions, error) {
	switch cfg.Type {
	case "local", "":
		return Sessions{store: &InMemoryStore{Cache: cache.New[string, Session](ttl, time.Minute)}}, nil
	case "redis":
		redisClient := redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Addr,
			Username: cfg.Redis.Username,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})
		return Sessions{store: &RedisStore{Client: redisClient, TTL: ttl}}, nil
	default:
		return Sessions{}, fmt.Errorf("unknown store type: %s", cfg.Type)
	}
}

// CreateSession creates a new session and returns a JWT token to be sent back to the client.
func (m Sessions) CreateSession(ctx context.Context, identity provider.Identity, r *http.Request) (Token, error) {
	// allocate a session ID
	sessionID := uuid.New().String()
	// create the session token that will be sent back to the client
	token := generateToken(sessionID, identity)
	// store a session in the data store
	var userAgent string
	if r != nil {
		userAgent = r.Header.Get("User-Agent")
	}
	now := time.Now()
	refreshSecret := generateRefreshToken()
	session := Session{
		ID:               sessionID,
		Identity:         identity,
		RefreshSecret:    refreshSecret[:],
		RefreshTokenHash: token.RefreshToken.hash(),
		IssuedAt:         now,
		UserAgent:        userAgent,
	}
	if err := m.put(ctx, token.Identity.Email, sessionID, session); err != nil {
		return token, err
	}
	return token, nil
}

// Validate validates that the session in the token exists in the store.  If found, Validate() updates
// the user agent and the last refresh time in the store. It returns the updated token.
func (m Sessions) Validate(ctx context.Context, token Token, r *http.Request) (Token, error) {
	// if the session doesn't exist, it's an error
	session, err := m.get(ctx, token.Identity.Email, token.SessionID)
	if err != nil {
		return token, err
	}

	// if the token has not expired and is still presenting the same refresh token, consider the token valid
	if !token.Expired() && token.RefreshToken.hash() == session.RefreshTokenHash {
		return token, nil
	}

	// either the token has expired, or the client is presenting a new refresh token (possibly the next rotated refresh token).
	// create a new token, rotating the refresh token.
	// rotateRefreshToken fails if the token's refresh token no longer matches the current or previous refresh token.

	token, session, err = m.rotateRefreshToken(token, session)
	if err != nil {
		return token, fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	// update the user agent in the store
	// trade-off: ideally, we'd update this (and a "last seen" timestamp) for each request. However,
	// concurrent requests could lead to one request rotating the refresh token and then
	// a second request writing back the old refresh token.
	if r != nil {
		session.UserAgent = r.Header.Get("User-Agent")
	}
	return token, m.update(ctx, token.Identity.Email, token.SessionID, session)
}

// rotateRefreshToken rotates the refresh token for a session. It returns the new token, session, and any error that occurred.
//
// In rotating the refresh token, we need to ensure that concurrent requests do not overwrite each other's changes.
// To protect against that, we keep track of the current refresh token and the previous refresh token.
// When we rotate, and we see that the client is presenting the previous refresh token, we accept it for a short
// period of time.
func (m Sessions) rotateRefreshToken(token Token, session Session) (Token, Session, error) {
	// we'll need to issue a new token. update the ID
	token.ID = uuid.New().String()

	// check that the refresh token matches the current or previous refresh token
	now := time.Now()
	switch token.RefreshToken.hash() {
	case session.RefreshTokenHash:
		// current refresh token: rotate it
		token.RefreshToken = token.RefreshToken.next(session.RefreshSecret)
		session.PreviousRefreshTokenHash = session.RefreshTokenHash
		session.RefreshTokenHash = token.RefreshToken.hash()
		session.RotatedAt = now
	case session.PreviousRefreshTokenHash:
		// previous refresh token: the refresh token was already rotated by another request.
		// only accept it during the grace period after rotation.
		if now.Sub(session.RotatedAt) > refreshTokenGracePeriod {
			return Token{}, Session{}, ErrInvalidRefreshToken
		}
		// next() returns the same successor i.e., the current refresh token.
		token.RefreshToken = token.RefreshToken.next(session.RefreshSecret)
	default:
		return Token{}, Session{}, ErrInvalidRefreshToken
	}
	token.ExpiresAt = jwt.NewNumericDate(now.Add(tokenExpiration))
	return token, session, nil
}

func (m Sessions) DeleteSession(ctx context.Context, email string, sessionID string) error {
	return m.del(ctx, email, sessionID)
}

// A store abstracts the storage of session data.
// Currently implemented with an in-memory cache and Redis.
type store interface {
	put(ctx context.Context, email string, sessionID string, session Session) error
	update(ctx context.Context, email string, sessionID string, session Session) error
	get(ctx context.Context, email string, sessionID string) (Session, error)
	del(ctx context.Context, email string, sessionID string) error
	Len(ctx context.Context) (int, error)
	List(ctx context.Context, email string) ([]Session, error)
}

var (
	_ store = (*InMemoryStore)(nil)
	_ store = (*RedisStore)(nil)
)

type InMemoryStore struct {
	Cache *cache.Cache[string, Session]
}

func (s InMemoryStore) put(_ context.Context, email string, sessionID string, session Session) error {
	s.Cache.Add(key(email, sessionID), session)
	return nil
}

func (s InMemoryStore) update(_ context.Context, email string, sessionID string, session Session) error {
	s.Cache.Update(key(email, sessionID), session)
	return nil
}

func (s InMemoryStore) get(_ context.Context, email string, sessionID string) (Session, error) {
	if session, ok := s.Cache.Get(key(email, sessionID)); ok {
		return session, nil
	}
	return Session{}, ErrSessionNotFound
}

func (s InMemoryStore) del(_ context.Context, email string, sessionID string) error {
	k := key(email, sessionID)
	if _, ok := s.Cache.Get(k); !ok {
		return ErrSessionNotFound
	}
	s.Cache.Remove(k)
	return nil
}

func (s InMemoryStore) Len(_ context.Context) (int, error) {
	match := fullScanKey("")
	var count int
	for k := range s.Cache.Iterate() {
		if strings.HasPrefix(k, match) {
			count++
		}
	}
	return count, nil
}

func (s InMemoryStore) List(_ context.Context, email string) ([]Session, error) {
	match := emailScanKey(email, "")
	sessions := make([]Session, 0, s.Cache.Len())
	for k, v := range s.Cache.Iterate() {
		if strings.HasPrefix(k, match) {
			sessions = append(sessions, v)
		}
	}
	return sessions, nil
}

type RedisStore struct {
	Client *redis.Client
	TTL    time.Duration
}

func (s RedisStore) put(ctx context.Context, email string, sessionID string, session Session) error {
	rawSession, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	return s.Client.Set(ctx, key(email, sessionID), rawSession, s.TTL).Err()
}

func (s RedisStore) update(ctx context.Context, email string, sessionID string, session Session) error {
	rawSession, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("json: %w", err)
	}
	value, err := s.Client.SetArgs(ctx, key(email, sessionID), rawSession, redis.SetArgs{
		Mode:    "XX",
		KeepTTL: true,
	}).Result()
	if errors.Is(err, redis.Nil) || value == "" {
		return ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	return nil
}

func (s RedisStore) get(ctx context.Context, email string, sessionID string) (Session, error) {
	rawSession, err := s.Client.Get(ctx, key(email, sessionID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, fmt.Errorf("redis: %w", err)
	}
	var session Session
	err = json.Unmarshal([]byte(rawSession), &session)
	if err != nil {
		return Session{}, fmt.Errorf("json: %w", err)
	}
	return session, nil
}

func (s RedisStore) del(ctx context.Context, email string, sessionID string) error {
	value, err := s.Client.Del(ctx, key(email, sessionID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redis: %w", err)
	}
	if errors.Is(err, redis.Nil) || value == 0 {
		return ErrSessionNotFound
	}
	return err
}

func (s RedisStore) Len(ctx context.Context) (int, error) {
	i := s.Client.Scan(ctx, 0, fullScanKey("*"), 100).Iterator()
	var found int
	for i.Next(ctx) {
		found++
	}
	return found, i.Err()
}

func (s RedisStore) List(ctx context.Context, email string) ([]Session, error) {
	match := emailScanKey(email, "*")
	cmds := make(map[string]*redis.StringCmd)
	pipe := s.Client.Pipeline()
	i := s.Client.
		Scan(ctx, 0, match, 100).
		Iterator()
	for i.Next(ctx) {
		k := i.Val()
		cmds[k] = pipe.Get(ctx, k)
	}
	if i.Err() != nil {
		return nil, fmt.Errorf("redis: %w", i.Err())
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("redis: %w", err)
	}
	sessions := make([]Session, 0, len(cmds))
	for _, cmd := range cmds {
		val, err := cmd.Result()
		// expired between scan & get
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("redis: %w", err)
		}
		var session Session
		if err = json.Unmarshal([]byte(val), &session); err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func key(email string, sessionID string) string {
	return strings.Join([]string{
		namespaceKeyPrefix,
		subsystemKeyPrefix,
		base64.StdEncoding.EncodeToString([]byte(email)), // base64 the email address, in case it contains cache glob characters or colons
		sessionID, // uuid generated at the server. no need to base64 encode it
	}, ":")
}

func emailScanKey(email string, glob string) string {
	return strings.Join([]string{
		namespaceKeyPrefix,
		subsystemKeyPrefix,
		base64.StdEncoding.EncodeToString([]byte(email)),
		glob,
	}, ":")
}

func fullScanKey(glob string) string {
	return strings.Join([]string{
		namespaceKeyPrefix,
		subsystemKeyPrefix,
		glob,
	}, ":")
}
