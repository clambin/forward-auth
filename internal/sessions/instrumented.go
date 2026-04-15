package sessions

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

var sessionCountMetric = prometheus.NewDesc("forward_auth_session_count", "Number of active sessions", nil, nil)

var _ prometheus.Collector = InstrumentedManager{}

type InstrumentedManager struct {
	*Manager
}

func (i InstrumentedManager) Describe(ch chan<- *prometheus.Desc) {
	ch <- sessionCountMetric
}

func (i InstrumentedManager) Collect(ch chan<- prometheus.Metric) {
	sessions, err := i.Manager.List(context.Background())
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(sessionCountMetric, prometheus.GaugeValue, float64(len(sessions)))
}
