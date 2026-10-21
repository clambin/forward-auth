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
	"github.com/clambin/forward-auth/internal/observability"
	"github.com/clambin/forward-auth/internal/session"
	"github.com/stretchr/testify/require"
)

// TestServer only tests if each route reaches the right handler and returns the correct status code
func TestServer(t *testing.T) {
	// verify that each target reaches the right handler
	cfg := configuration.Default()
	cfg.Authn.Provider.Type = "github"
	an, err := authn.New(t.Context(), cfg)
	require.NoError(t, err)
	az := &authz.Authorizer{Rules: cfg.Authz.Rules, Groups: cfg.Authz.Groups}
	sessions, err := session.New(
		5*time.Minute, cfg.Server, cfg.Storage, an, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	healthz := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	hInt, hExt := New(cfg.Server, sessions, az, observability.GetMetrics(), healthz, slog.New(slog.DiscardHandler))

	// internal

	// forward-auth
	req := httptest.NewRequest(http.MethodGet, forwardPath, nil)
	resp := httptest.NewRecorder()
	hInt.ServeHTTP(resp, req)
	require.Equal(t, http.StatusSeeOther, resp.Code)

	// health check
	req = httptest.NewRequest(http.MethodGet, cfg.Server.HealthPath, nil)
	resp = httptest.NewRecorder()
	hInt.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// external

	// login
	req = httptest.NewRequest(http.MethodGet, loginPath, nil)
	resp = httptest.NewRecorder()
	hExt.ServeHTTP(resp, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)

	// html
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	resp = httptest.NewRecorder()
	hExt.ServeHTTP(resp, req)
	require.Equal(t, http.StatusSeeOther, resp.Code)

	// API
	req = httptest.NewRequest(http.MethodGet, "/api/sessions/list", nil)
	resp = httptest.NewRecorder()
	hExt.ServeHTTP(resp, req)
	require.Equal(t, http.StatusUnauthorized, resp.Code)
}
