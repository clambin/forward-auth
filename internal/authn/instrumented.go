package authn

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

var _ prometheus.Collector = (*InstrumentedAuthenticator)(nil)

var stateCountMetric = prometheus.NewDesc("forward_auth_state_count", "Number of active states", nil, nil)

type InstrumentedAuthenticator struct {
	*Authenticator
}

func (a InstrumentedAuthenticator) Describe(ch chan<- *prometheus.Desc) {
	ch <- stateCountMetric
}

func (a InstrumentedAuthenticator) Collect(ch chan<- prometheus.Metric) {
	count, err := a.states.Len(context.Background())
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(stateCountMetric, prometheus.GaugeValue, float64(count))
}
