package testutils

import (
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRedisTestContainer(t *testing.T) {
	endpoint := RedisTestContainer(t)

	c := redis.NewClient(&redis.Options{Addr: endpoint})
	err := c.Ping(t.Context()).Err()
	require.NoError(t, err)
}
