package cache

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

var _ prometheus.Collector = InstrumentedCache[Cache[int]]{}

type Store interface {
	Len(context.Context) (int, error)
}

type InstrumentedCache[S Store] struct {
	Cache S
	*prometheus.Desc
}

func (i InstrumentedCache[S]) Describe(ch chan<- *prometheus.Desc) {
	ch <- i.Desc
}

func (i InstrumentedCache[S]) Collect(ch chan<- prometheus.Metric) {
	count, err := i.Cache.Len(context.Background())
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			i.Desc,
			prometheus.GaugeValue,
			float64(count),
		)
	}
}
