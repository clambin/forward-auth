package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/server/middleware"
	"github.com/clambin/forward-auth/internal/sessions"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	// verify that each target reaches the right handler
	cfg := configuration.DefaultConfiguration
	s, _ := sessions.New(5*time.Minute, cfg.Storage)
	an, _ := authn.New(t.Context(), cfg)
	az, _ := authz.New(cfg.Authz.Rules)

	h := New(cfg.Server, s, an, az, nil, middleware.GetMetrics(), slog.New(slog.DiscardHandler))

	// forward-auth
	req := httptest.NewRequest(http.MethodGet, "/api/auth/forwardauth", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusSeeOther, resp.Code)

	// login
	req = httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)

	// healthcheck
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// API
	req = httptest.NewRequest(http.MethodGet, "/api/sessions/list", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusUnauthorized, resp.Code)
}
