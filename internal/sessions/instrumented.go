package sessions

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

var sessionCountMetric = prometheus.NewDesc("forward_auth_session_count", "Number of active sessions", nil, nil)

var _ prometheus.Collector = InstrumentedUserSessionManager{}

type InstrumentedUserSessionManager struct {
	*UserSessionManager
}

func (i InstrumentedUserSessionManager) Describe(ch chan<- *prometheus.Desc) {
	ch <- sessionCountMetric
}

func (i InstrumentedUserSessionManager) Collect(ch chan<- prometheus.Metric) {
	sessions, err := i.List(context.Background())
	if err != nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(sessionCountMetric, prometheus.GaugeValue, float64(len(sessions)))
}
