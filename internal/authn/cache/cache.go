package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"codeberg.org/clambin/go-common/cache"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/redis/go-redis/v9"
)

// maxScanKeys is the maximum number of keys to return in a single Redis scan.
const maxScanKeys = 10

var (
	ErrNotFound = errors.New("not found")
)

// Cache is a generic cache interface, storing values of type T. The key type is always string.
type Cache[T any] interface {
	// Set adds a new item to the cache.
	Set(ctx context.Context, id string, val T) error
	// GetAndDelete atomically returns and removes an item from the cache
	// or returns ErrNotFound if an item does not exist.
	GetAndDelete(ctx context.Context, id string) (T, error)
	// Len returns the number of items in the cache.
	Len(ctx context.Context) (int, error)
}

var (
	_ Cache[string] = (*localCache[string])(nil)
	_ Cache[string] = (*redisCache[string])(nil)
)

// New creates a new cache of the type specified in configuration.Type, for values of type T.
// Supports an in-memory cache (type "local" or blank) and a Redis cache (type "redis").
//
// ttl specifies when items expire from the cache.
// prefix is used to prefix the keys of the cache to prevent name collisions when the physical cache is shared across multiple components.
// Local caches ignore the prefix as they cannot be shared across services.
func New[T any](ttl time.Duration, prefix string, configuration configuration.StorageConfiguration) (Cache[T], error) {
	var c Cache[T]
	switch configuration.Type {
	case "local", "":
		c = &localCache[T]{
			cache: cache.New[string, T](ttl, time.Minute),
		}
	case "redis":
		c = &redisCache[T]{
			ttl:    ttl,
			prefix: prefix + ":",
			client: redis.NewClient(&redis.Options{
				Addr:     configuration.Redis.Addr,
				Username: configuration.Redis.Username,
				Password: configuration.Redis.Password,
				DB:       configuration.Redis.DB,
			}),
		}
	default:
		return nil, fmt.Errorf("unsupported cache type: %s", configuration.Type)
	}
	return c, nil
}

type localCache[T any] struct {
	cache *cache.Cache[string, T]
}

func (c *localCache[T]) Set(_ context.Context, id string, val T) error {
	c.cache.Add(id, val)
	return nil
}

func (c *localCache[T]) GetAndDelete(_ context.Context, id string) (T, error) {
	value, ok := c.cache.GetAndRemove(id)
	if !ok {
		return value, ErrNotFound
	}
	return value, nil
}

func (c *localCache[T]) Len(_ context.Context) (int, error) {
	return c.cache.Len(), nil
}

type redisCache[T any] struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

func (c *redisCache[T]) Set(ctx context.Context, id string, val T) error {
	body, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.prefixedID(id), string(body), c.ttl).Err()
}

func (c *redisCache[T]) GetAndDelete(ctx context.Context, id string) (T, error) {
	var v T
	value, err := c.client.GetDel(ctx, c.prefixedID(id)).Result()
	if errors.Is(err, redis.Nil) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, fmt.Errorf("redis getdel: %w", err)
	}
	err = json.Unmarshal([]byte(value), &v)
	return v, err
}

func (c *redisCache[T]) Delete(ctx context.Context, id string) error {
	err := c.client.Del(ctx, c.prefixedID(id)).Err()
	if errors.Is(err, redis.Nil) {
		err = nil
	}
	return err
}

func (c *redisCache[T]) Len(ctx context.Context) (int, error) {
	var found int
	i := c.client.Scan(ctx, 0, c.prefixedID("*"), maxScanKeys).Iterator()
	for i.Next(ctx) {
		found++
	}
	if i.Err() != nil {
		return 0, fmt.Errorf("redis scan: %w", i.Err())
	}
	return found, nil
}

func (c *redisCache[T]) prefixedID(id string) string {
	if c.prefix == "" {
		return id
	}
	return c.prefix + id
}
