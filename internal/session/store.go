package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"codeberg.org/clambin/go-common/cache"
	"github.com/redis/go-redis/v9"
)

// The store interface abstracts the storage of session data.
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
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("redis: %w", err)
	}
	if errors.Is(err, redis.Nil) || value == "" {
		return ErrSessionNotFound
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
		sessionID, // uuid generated at the server. no need to base64 it
	}, ":")
}

func emailScanKey(email string, glob string) string {
	return key(email, glob)
}

func fullScanKey(glob string) string {
	return strings.Join([]string{
		namespaceKeyPrefix,
		subsystemKeyPrefix,
		glob,
	}, ":")
}
