package testutils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func RedisTestContainer(tb testing.TB) string {
	tb.Helper()
	ctx := tb.Context()
	c, err := tcredis.Run(ctx, "redis:8.10.2")
	require.NoError(tb, err)
	endpoint, err := c.Endpoint(ctx, "")
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, c.Terminate(context.Background())) })
	return endpoint
}
