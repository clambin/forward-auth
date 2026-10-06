package cache

import (
	"strings"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstrumentedCache(t *testing.T) {
	c, _ := New[int](15*time.Minute, "foo", configuration.StorageConfiguration{})
	require.NoError(t, c.Set(t.Context(), "foo", 1))

	i := InstrumentedCache[Cache[int]]{
		Cache: c,
		Desc:  prometheus.NewDesc("cache_size", "Size of the cache", nil, nil),
	}
	assert.NoError(t, testutil.CollectAndCompare(i, strings.NewReader(`
# HELP cache_size Size of the cache
# TYPE cache_size gauge
cache_size 1
`)))
}
