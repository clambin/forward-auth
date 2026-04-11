package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"codeberg.org/clambin/go-common/cache"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/redis/go-redis/v9"
)

var (
	ErrNotFound = errors.New("not found")
)

// Cache is a generic cache interface, storing values of type T. The key type is always string.
type Cache[T any] interface {
	// Set adds a new item to the cache.
	Set(ctx context.Context, id string, val T) error
	// Update updates an existing item in the cache without changing its expiration time.
	Update(ctx context.Context, id string, val T) error
	// List returns all non-expired items from the cache.
	List(ctx context.Context) (map[string]T, error)
	// Get returns an item from the cache, or ErrNotFound if an item does not exist.
	Get(ctx context.Context, id string) (T, error)
	// Delete removes an item from the cache. If the item does not exist, no error is returned,
	// as the item may have expired naturally.
	Delete(ctx context.Context, id string) error
	// TTL returns the expiration time of the cache.
	TTL() time.Duration
}

var (
	_ Cache[string] = (*localCache[string])(nil)
	_ Cache[string] = (*redisCache[string])(nil)
)

// New creates a new cache for values of type T of the type specified in configuration.Type.
// Supports an in-memory cache (type "local" or blank) and a Redis cache (type "redis").
//
// ttl specifies when items expire from the cache.
// prefix is used to prefix the keys of the cache to prevent name collisions when the cache is shared across multiple services or instances.
// Local caches ignore the prefix and should not be shared across services.
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

func (c *localCache[T]) Update(_ context.Context, id string, val T) error {
	c.cache.Update(id, val)
	return nil
}

func (c *localCache[T]) Get(_ context.Context, id string) (T, error) {
	var err error
	value, ok := c.cache.Get(id)
	if !ok {
		err = ErrNotFound
	}
	return value, err
}

func (c *localCache[T]) Delete(_ context.Context, id string) error {
	c.cache.Remove(id)
	return nil
}

func (c *localCache[T]) TTL() time.Duration {
	return c.cache.GetDefaultExpiration()
}

func (c *localCache[T]) List(_ context.Context) (map[string]T, error) {
	return maps.Collect(c.cache.Iterate()), nil
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

func (c *redisCache[T]) Update(ctx context.Context, id string, val T) error {
	body, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return c.client.SetArgs(ctx, c.prefixedID(id), string(body), redis.SetArgs{KeepTTL: true}).Err()
}

func (c *redisCache[T]) Get(ctx context.Context, id string) (T, error) {
	var v T
	value, err := c.client.Get(ctx, c.prefixedID(id)).Result()
	if errors.Is(err, redis.Nil) {
		return v, ErrNotFound
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

func (c *redisCache[T]) TTL() time.Duration {
	return c.ttl
}

func (c *redisCache[T]) List(ctx context.Context) (map[string]T, error) {
	keys, err := c.client.Keys(ctx, c.prefixedID("*")).Result()
	if err != nil {
		return nil, fmt.Errorf("redis keys: %w", err)
	}
	items := make(map[string]T, len(keys))
	for _, key := range keys {
		id := c.unprefixedKey(key)
		v, err := c.Get(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("redis get: %w", err)
		}
		items[id] = v
	}
	return items, nil
}

func (c *redisCache[T]) prefixedID(id string) string {
	if c.prefix == "" {
		return id
	}
	return c.prefix + id
}

func (c *redisCache[T]) unprefixedKey(key string) string {
	if c.prefix != "" {
		key = strings.TrimPrefix(key, c.prefix)
	}
	return key
}
