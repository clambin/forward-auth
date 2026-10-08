package observability

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestInstrumentedStore(t *testing.T) {
	c := InstrumentedStore{
		Store: counterFunc(func(ctx context.Context) (int, error) {
			return 10, nil
		}),
		Desc: prometheus.NewDesc("counter", "counter", nil, nil),
	}

	assert.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(`
# HELP counter counter
# TYPE counter gauge
counter 10
`)))
}

type counterFunc (func(context.Context) (int, error))

func (c counterFunc) Len(ctx context.Context) (int, error) {
	return c(ctx)
}
