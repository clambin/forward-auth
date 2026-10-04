package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

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
	// Expire sets the expiration time of an item in the cache.
	Expire(ctx context.Context, id string, ttl time.Duration) error
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
			cache: make(map[string]localCacheEntry[T]),
			ttl:   ttl,
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

func MustNew[T any](ttl time.Duration, prefix string, configuration configuration.StorageConfiguration) Cache[T] {
	c, err := New[T](ttl, prefix, configuration)
	if err != nil {
		panic(err)
	}
	return c
}

// TODO: a localCache never shrinks :(

type localCacheEntry[T any] struct {
	value T
	ttl   time.Time
}
type localCache[T any] struct {
	cache map[string]localCacheEntry[T]
	ttl   time.Duration
	mu    sync.Mutex
}

func (c *localCache[T]) Set(_ context.Context, id string, val T) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[id] = localCacheEntry[T]{value: val, ttl: time.Now().Add(c.ttl)}
	return nil
}

func (c *localCache[T]) Update(_ context.Context, id string, val T) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[id]
	if !ok {
		return ErrNotFound
	}
	entry.value = val
	c.cache[id] = entry
	return nil
}

func (c *localCache[T]) Get(_ context.Context, id string) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	entry, ok := c.cache[id]
	if !ok || time.Now().After(entry.ttl) {
		err = ErrNotFound
	}
	return entry.value, err
}

func (c *localCache[T]) GetAndDelete(_ context.Context, id string) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[id]
	if !ok || time.Now().After(entry.ttl) {
		return entry.value, ErrNotFound
	}
	delete(c.cache, id)
	return entry.value, nil
}

func (c *localCache[T]) Delete(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, id)
	return nil
}

func (c *localCache[T]) Expire(_ context.Context, id string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[id]
	if !ok || time.Now().After(entry.ttl) {
		return ErrNotFound
	}
	entry.ttl = time.Now().Add(ttl)
	c.cache[id] = entry
	return nil
}

func (c *localCache[T]) TTL() time.Duration {
	return c.ttl
}

func (c *localCache[T]) List(_ context.Context) (map[string]T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make(map[string]T, len(c.cache))
	for id, entry := range c.cache {
		if time.Now().After(entry.ttl) {
			continue
		}
		result[id] = entry.value
	}
	return result, nil
}

func (c *localCache[T]) Len(ctx context.Context) (int, error) {
	entries, err := c.List(ctx)
	return len(entries), err
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

func (c *redisCache[T]) Expire(ctx context.Context, id string, ttl time.Duration) error {
	return c.client.Expire(ctx, c.prefixedID(id), ttl).Err()
}

func (c *redisCache[T]) TTL() time.Duration {
	return c.ttl
}

func (c *redisCache[T]) List(ctx context.Context) (map[string]T, error) {
	keys, err := c.scan(ctx, c.prefixedID("*"))
	if err != nil {
		return nil, err
	}

	// instead of iterating over all keys and performing a GET for each key,
	// we can use a pipeline to get all values in a single request
	items := make(map[string]T, len(keys))
	pipe := c.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))
	for i, key := range keys {
		cmds[i] = pipe.Get(ctx, key)
	}

	// run the pipeline
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("redis get: %w", err)
	}

	// collect the results
	for i, cmd := range cmds {
		if errors.Is(cmd.Err(), redis.Nil) {
			// Key expired between SCAN and GET.
			continue
		}
		if err := cmd.Err(); err != nil {
			return nil, fmt.Errorf("redis get: %w", err)
		}

		var v T
		if err := json.Unmarshal([]byte(cmd.Val()), &v); err != nil {
			return nil, fmt.Errorf("json: unmarshal %q: %w", keys[i], err)
		}
		// these are raw Redis gets, so need to strip the prefix
		items[c.unprefixedKey(keys[i])] = v
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
