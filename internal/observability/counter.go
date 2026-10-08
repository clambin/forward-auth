package observability

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

type Store interface {
	Len(context.Context) (int, error)
}

var _ prometheus.Collector = InstrumentedStore{}

type InstrumentedStore struct {
	Store Store
	Desc  *prometheus.Desc
}

func (i InstrumentedStore) Describe(descs chan<- *prometheus.Desc) {
	descs <- i.Desc
}

func (i InstrumentedStore) Collect(metrics chan<- prometheus.Metric) {
	if count, err := i.Store.Len(context.Background()); err == nil {
		metrics <- prometheus.MustNewConstMetric(i.Desc, prometheus.GaugeValue, float64(count))
	}
}
