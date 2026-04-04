package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"codeberg.org/clambin/go-common/cache"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/redis/go-redis/v9"
)

var (
	ErrNotFound = errors.New("not found")
)

type Cache[T any] interface {
	Set(ctx context.Context, id string, val T) error
	Get(ctx context.Context, id string) (T, error)
	Delete(ctx context.Context, id string) error
	TTL() time.Duration
	Update(ctx context.Context, id string, val T) error
	List(ctx context.Context) (map[string]T, error)
}

var (
	_ Cache[string] = (*localCache[string])(nil)
	_ Cache[string] = (*redisCache[string])(nil)
)

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
	if value, ok := c.cache.Get(id); ok {
		return value, nil
	}
	var zero T
	return zero, ErrNotFound
}

func (c *localCache[T]) Delete(_ context.Context, id string) error {
	c.cache.Remove(id)
	return nil
}

func (c *localCache[T]) TTL() time.Duration {
	return c.cache.GetDefaultExpiration()
}

func (c *localCache[T]) List(_ context.Context) (map[string]T, error) {
	items := make(map[string]T)
	for k, v := range c.cache.Iterate() {
		items[k] = v
	}
	return items, nil
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
	return c.client.Del(ctx, c.prefixedID(id)).Err()
}

func (c *redisCache[T]) TTL() time.Duration {
	return c.ttl
}

func (c *redisCache[T]) List(ctx context.Context) (map[string]T, error) {
	keys, err := c.client.Keys(ctx, c.prefixedID("*")).Result()
	if err != nil {
		return nil, err
	}
	items := make(map[string]T, len(keys))
	for _, key := range keys {
		id := c.unprefixedKey(key)
		if v, err := c.Get(ctx, id); err == nil {
			items[id] = v
		}
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
