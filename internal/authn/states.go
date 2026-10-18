package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"codeberg.org/clambin/go-common/cache"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/redis/go-redis/v9"
)

var (
	ErrInvalidCSRFState = errors.New("invalid csrf state")
)

type states struct {
	store
}

func newStates(ttl time.Duration, cfg configuration.StorageConfiguration) (states, error) {
	var store store
	switch cfg.Type {
	case "local", "":
		store = &inMemoryStore{
			cache: cache.New[string, string](ttl, time.Minute),
		}
	case "redis":
		store = &redisStore{
			ttl: ttl,
			client: redis.NewClient(&redis.Options{
				Addr:     cfg.Redis.Addr,
				Username: cfg.Redis.Username,
				Password: cfg.Redis.Password,
				DB:       cfg.Redis.DB,
			}),
		}
	default:
		return states{}, fmt.Errorf("invalid storage type: %s", cfg.Type)
	}

	return states{store: store}, nil
}

// Allocate creates a new CSRF state and stores it in the state store.
func (s *states) Allocate(ctx context.Context, url string) (string, error) {
	const size = 32 // 256 bits
	var b [size]byte
	_, _ = rand.Read(b[:])
	state := hex.EncodeToString(b[:])
	return state, s.set(ctx, key(state), url)
}

// Validate validates that the CSRF state exists in the state store.
func (s *states) Validate(ctx context.Context, state string) (string, error) {
	return s.getAndDelete(ctx, key(state))

}

// Len returns the number of CSRF states in the state store.
func (s *states) Len(ctx context.Context) (int, error) {
	return s.len(ctx)
}

// store is an interface for storing and retrieving CSRF states.
type store interface {
	set(context.Context, string, string) error
	getAndDelete(context.Context, string) (string, error)
	len(context.Context) (int, error)
}

var (
	_ store = (*inMemoryStore)(nil)
	_ store = (*redisStore)(nil)
)

type inMemoryStore struct {
	cache *cache.Cache[string, string]
}

func (i *inMemoryStore) set(_ context.Context, key string, value string) error {
	i.cache.Add(key, value)
	return nil
}

func (i *inMemoryStore) getAndDelete(_ context.Context, key string) (string, error) {
	if value, ok := i.cache.GetAndRemove(key); ok {
		return value, nil
	}
	return "", ErrInvalidCSRFState
}

func (i *inMemoryStore) len(_ context.Context) (int, error) {
	return i.cache.Len(), nil
}

type redisStore struct {
	client *redis.Client
	ttl    time.Duration
}

func (r redisStore) set(ctx context.Context, key string, value string) error {
	return r.client.Set(ctx, key, value, r.ttl).Err()
}

func (r redisStore) getAndDelete(ctx context.Context, s string) (string, error) {
	value, err := r.client.GetDel(ctx, s).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrInvalidCSRFState
	}
	return value, err
}

func (r redisStore) len(ctx context.Context) (int, error) {
	i := r.client.Scan(ctx, 0, key("*"), 100).Iterator()
	var found int
	for i.Next(ctx) {
		found++
	}
	return found, i.Err()
}

func key(state string) string {
	return strings.Join([]string{
		"forward-auth",
		"state",
		state,
	}, ":")
}
