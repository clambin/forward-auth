package cache

import (
	"errors"
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

			// test update doesn't affect remaining TTL
			// note: this is a bit flaky. use syncTest?
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			time.Sleep(ttl / 2)
			require.NoError(t, c.Update(ctx, "foo", "baz"))
			value, err := c.Get(ctx, "foo")
			require.NoError(t, err)
			assert.Equal(t, "baz", value)
			// item should expire around original TTL, not TTL from update time
			time.Sleep(3 * ttl / 4)
			_, err = c.Get(ctx, "foo")
			require.ErrorIs(t, err, ErrNotFound)

			// test get-and-delete
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			value, err = c.GetAndDelete(ctx, "foo")
			assert.Equal(t, "bar", value)
			require.NoError(t, err)
			_, err = c.GetAndDelete(ctx, "foo")
			require.ErrorIs(t, err, ErrNotFound)
		})
	}
}
