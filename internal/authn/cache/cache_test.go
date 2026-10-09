package cache

import (
	"context"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestCache(t *testing.T) {
	ctx := t.Context()
	c, err := tcredis.Run(ctx, "ghcr.io/valkey-io/valkey:latest")
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

			// add a value
			require.NoError(t, c.Set(ctx, "foo", "bar"))

			// test len
			count, err := c.Len(context.Background())
			require.NoError(t, err)
			assert.Equal(t, 1, count)

			// test get-and-delete
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			value, err := c.GetAndDelete(ctx, "foo")
			assert.Equal(t, "bar", value)
			require.NoError(t, err)

			// try again and verify the key is gone
			_, err = c.GetAndDelete(ctx, "foo")
			require.ErrorIs(t, err, ErrNotFound)

		})
	}
}

func TestRedisCache_Len(t *testing.T) {
	ctx := t.Context()
	c, err := tcredis.Run(ctx, "ghcr.io/valkey-io/valkey:latest")
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
