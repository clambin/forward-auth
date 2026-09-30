package cache

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestCache(t *testing.T) {
	ctx := t.Context()
	c, err := tcredis.Run(ctx, "redis:latest")
	require.NoError(t, err)
	endpoint, err := c.Endpoint(ctx, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	tests := []struct {
		name string
		cfg  configuration.StorageConfiguration
		err  require.ErrorAssertionFunc
	}{
		{"in-memory", configuration.StorageConfiguration{}, require.NoError},
		{"redis", configuration.StorageConfiguration{Type: "redis", Redis: configuration.StorageRedisConfiguration{Addr: endpoint}}, require.NoError},
		{"invalid", configuration.StorageConfiguration{Type: "invalid"}, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const ttl = time.Second
			c, err := New[string](ttl, "prefix", tt.cfg)
			tt.err(t, err)

			if err != nil {
				return
			}

			assert.Equal(t, ttl, c.TTL())

			// add a value
			require.NoError(t, c.Set(ctx, "foo", "bar"))

			// list values
			items, err := c.List(ctx)
			require.NoError(t, err)
			require.Len(t, items, 1)
			require.Equal(t, "bar", items["foo"])

			// delete the value
			require.NoError(t, c.Delete(ctx, "foo"))

			// test expiration
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			require.Eventually(t, func() bool {
				_, err = c.Get(ctx, "foo")
				return errors.Is(err, ErrNotFound)
			}, 2*ttl, time.Millisecond)

			// test get-and-delete
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			value, err := c.GetAndDelete(ctx, "foo")
			assert.Equal(t, "bar", value)
			require.NoError(t, err)
			_, err = c.Get(ctx, "foo")
			require.ErrorIs(t, err, ErrNotFound)

			// quick len test
			count, err := c.Len(context.Background())
			require.NoError(t, err)
			assert.Equal(t, 0, count)
		})
	}
}

func TestRedisCache_Len(t *testing.T) {
	ctx := t.Context()
	c, err := tcredis.Run(ctx, "redis:latest")
	require.NoError(t, err)
	endpoint, err := c.Endpoint(ctx, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	cfg := configuration.StorageConfiguration{
		Type:  "redis",
		Redis: configuration.StorageRedisConfiguration{Addr: endpoint},
	}

	cc, err := New[string](time.Second, "prefix", cfg)
	require.NoError(t, err)

	count, err := cc.Len(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	require.NoError(t, cc.Set(context.Background(), "foo", "bar"))
	require.NoError(t, cc.Set(context.Background(), "baz", "qux"))

	count, err = cc.Len(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func BenchmarkRedisCache_List(b *testing.B) {
	// Previous:
	// BenchmarkRedisCache_List/1-10  	    5860	    199843 ns/op	    1091 B/op	      25 allocs/op
	// BenchmarkRedisCache_List/10-10 	    1026	   1164240 ns/op	    5607 B/op	     151 allocs/op
	// BenchmarkRedisCache_List/100-10 	     100	  10651993 ns/op	   52579 B/op	    1321 allocs/op
	// BenchmarkRedisCache_List/1000-10       10	 106691917 ns/op	  589982 B/op	   13076 allocs/op
	// Pipelined:
	// BenchmarkRedisCache_List/1-10  	    5702	    199061 ns/op	    1219 B/op	      31 allocs/op
	// BenchmarkRedisCache_List/10-10 	    4447	    280625 ns/op	    5799 B/op	     126 allocs/op
	// BenchmarkRedisCache_List/100-10      1106	   1124103 ns/op	   52428 B/op	     939 allocs/op
	// BenchmarkRedisCache_List/1000-10	     124	   9669339 ns/op	  577494 B/op	    9098 allocs/op

	ctx := b.Context()
	c, err := tcredis.Run(ctx, "redis:latest")
	require.NoError(b, err)
	endpoint, err := c.Endpoint(ctx, "")
	require.NoError(b, err)
	b.Cleanup(func() { _ = c.Terminate(ctx) })

	cfg := configuration.StorageConfiguration{
		Type:  "redis",
		Redis: configuration.StorageRedisConfiguration{Addr: endpoint},
	}

	cache, err := New[string](time.Hour, "prefix", cfg)
	require.NoError(b, err)

	for exp := range 4 {
		expectedKeys := int(math.Pow(10, float64(exp)))
		b.Run(strconv.Itoa(expectedKeys), func(b *testing.B) {
			// populate cache with expectedKeys items
			for i := range expectedKeys {
				require.NoError(b, cache.Set(ctx, fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i)))
				require.NoError(b, cache.Set(ctx, fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i)))
			}

			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				keys, err := cache.List(ctx)
				require.NoError(b, err)
				require.Len(b, keys, expectedKeys)
			}
		})
	}
}
