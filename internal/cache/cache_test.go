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

func TestBackEnd(t *testing.T) {
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
			// add the value again
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			// wait for the value to expire
			require.Eventually(t, func() bool {
				_, err = c.Get(ctx, "foo")
				return errors.Is(err, ErrNotFound)
			}, 2*ttl, time.Millisecond)
			// add the value again
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			// update the value
			time.Sleep(ttl / 2) // this is a bit flaky. may regret this later
			require.NoError(t, c.Update(ctx, "foo", "baz"))
			// wait for the value to expire
			require.Eventually(t, func() bool {
				_, err = c.Get(ctx, "foo")
				return errors.Is(err, ErrNotFound)
			}, ttl, time.Millisecond)
		})
	}
}
