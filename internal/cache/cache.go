package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
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
	// Update updates an existing item in the cache without changing its expiration time.
	Update(ctx context.Context, id string, val T) error
	// List returns all non-expired items from the cache.
	List(ctx context.Context) (map[string]T, error)
	// Get returns an item from the cache, or ErrNotFound if an item does not exist.
	Get(ctx context.Context, id string) (T, error)
	// GetAndDelete atomically returns and removes an item from the cache
	// or returns ErrNotFound if an item does not exist.
	GetAndDelete(ctx context.Context, id string) (T, error)
	// Delete removes an item from the cache. If the item does not exist, no error is returned,
	// as the item may have expired naturally.
	Delete(ctx context.Context, id string) error
	// TTL returns the expiration time of the cache.
	TTL() time.Duration
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

func (c *localCache[T]) GetAndDelete(_ context.Context, id string) (T, error) {
	var err error
	value, ok := c.cache.GetAndRemove(id)
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
	if err != nil {
		return v, fmt.Errorf("redis get: %w", err)
	}
	err = json.Unmarshal([]byte(value), &v)
	return v, err
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

func (c *redisCache[T]) TTL() time.Duration {
	return c.ttl
}

func (c *redisCache[T]) List(ctx context.Context) (map[string]T, error) {
	// Keys() is quite heavy on a redis server and locks the single-threaded server while getting all matching keys.
	// Better: perform an iterative Scan() to get all matching keys.
	// For small installations, with low number of keys, it's not really a big problem.
	keys, err := c.scan(ctx, c.prefixedID("*"))
	if err != nil {
		return nil, err
	}
	items := make(map[string]T, len(keys))

	for _, key := range keys {
		id := c.unprefixedKey(key)
		v, err := c.Get(ctx, id)
		if errors.Is(err, ErrNotFound) {
			// key expired between listing it and getting its content
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("redis get: %w", err)
		}
		items[id] = v
	}
	return items, nil
}

func (c *redisCache[T]) Len(ctx context.Context) (int, error) {
	keys, err := c.scan(ctx, c.prefixedID("*"))
	return len(keys), err
}

func (c *redisCache[T]) scan(ctx context.Context, match string) ([]string, error) {
	// collect keys in a map so we can deduplicate
	keys := make(map[string]struct{})
	var cursor uint64
	for {
		// use scan rather than keys to prevent locking Redis
		cmd := c.client.Scan(ctx, cursor, match, maxScanKeys)
		var err error
		var newKeys []string
		if newKeys, cursor, err = cmd.Result(); err != nil { // && !errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("redis scan: %w", err)
		}
		for _, newKey := range newKeys {
			keys[newKey] = struct{}{}
		}
		if cursor == 0 {
			break
		}
	}
	return slices.Collect(maps.Keys(keys)), nil
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
