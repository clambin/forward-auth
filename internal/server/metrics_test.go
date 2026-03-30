package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestMetrics(t *testing.T) {
	m := GetMetrics()

	r := prometheus.NewPedanticRegistry()
	r.MustRegister(m)

	h := m.mw("test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for range 5 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://localhost:8080", nil))
	}

	const want = `
# HELP http_requests_total total requests processed
# TYPE http_requests_total counter
http_requests_total{code="200",handler="test",method="get"} 5
`
	assert.NoError(t, testutil.CollectAndCompare(r, strings.NewReader(want), "http_requests_total"))
	assert.Equal(t, 1, testutil.CollectAndCount(r, "http_request_duration_seconds"))
}
