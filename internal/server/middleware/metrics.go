package middleware

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var _ prometheus.Collector = Metrics{}

// Metrics provides HTTP request metrics for each handler.
type Metrics struct {
	counter  *prometheus.CounterVec
	duration prometheus.ObserverVec
}

// GetMetrics returns a Metrics instance.
func GetMetrics() Metrics {
	return Metrics{
		counter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "http_requests_total",
				Help:        "total requests processed",
				ConstLabels: nil,
			},
			[]string{"handler", "code", "method"},
		),
		duration: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       "http_request_duration_seconds",
				Help:       "request duration in seconds",
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			},
			[]string{"handler", "code", "method"},
		),
	}
}

// Describe implements prometheus.Collector.
func (m Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.counter.Describe(ch)
	m.duration.Describe(ch)
}

// Collect implements prometheus.Collector.
func (m Metrics) Collect(ch chan<- prometheus.Metric) {
	m.counter.Collect(ch)
	m.duration.Collect(ch)
}

// InstrumentedHandler returns a middleware that instruments the given handler with the counter and duration metrics.
func (m Metrics) InstrumentedHandler(handler string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return withHandlerInCtx(handler)(
			instrumentedHandlerCounter(m.counter)(
				instrumentedHandlerDuration(m.duration)(next),
			),
		)
	}
}

type handlerCtxKey struct{}

func handlerFromCtx(ctx context.Context) string {
	return ctx.Value(handlerCtxKey{}).(string)
}

// withHandlerInCtx returns a middleware that adds the given handler name to the request context,
// so that it can be extracted by instrumentedHandlerCounter and instrumentedHandlerDuration.
func withHandlerInCtx(handler string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), handlerCtxKey{}, handler)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// instrumentedHandlerCounter returns a promhttp.InstrumentHandlerCounter handler with an added "handler" label,
// whose value is extracted from the request context.
func instrumentedHandlerCounter(c *prometheus.CounterVec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return promhttp.InstrumentHandlerCounter(c, next, promhttp.WithLabelFromCtx("handler", handlerFromCtx))
	}
}

// instrumentedHandlerDuration returns a promhttp.InstrumentHandlerDuration handler with an added "handler" label,
// whose value is extracted from the request context.
func instrumentedHandlerDuration(c prometheus.ObserverVec) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return promhttp.InstrumentHandlerDuration(c, next, promhttp.WithLabelFromCtx("handler", handlerFromCtx))
	}
}
