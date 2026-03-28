package cache

import (
	"errors"
	"testing"
	"time"

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
		cfg  Configuration
		err  require.ErrorAssertionFunc
	}{
		{"in-memory", Configuration{}, require.NoError},
		{"redis", Configuration{Type: "redis", Redis: RedisConfiguration{Addr: endpoint}}, require.NoError},
		{"invalid", Configuration{Type: "invalid"}, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const ttl = time.Second
			c, err := New[string](ttl, "", tt.cfg)
			tt.err(t, err)

			if err != nil {
				return
			}

			assert.Equal(t, ttl, c.TTL())

			// add a value
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			// delete the value
			require.NoError(t, c.Delete(ctx, "foo"))
			// add the value again
			require.NoError(t, c.Set(ctx, "foo", "bar"))
			// wait for the value to expire
			require.Eventually(t, func() bool {
				_, err = c.Get(ctx, "foo")
				return errors.Is(err, ErrNotFound)
			}, 2*ttl, time.Millisecond)
		})
	}
}
