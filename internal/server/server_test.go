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
	"github.com/clambin/forward-auth/internal/forwardauth"
	"github.com/clambin/forward-auth/internal/observability"
	"github.com/stretchr/testify/require"
)

// TestServer only tests if all the routes reach the right handler
func TestServer(t *testing.T) {
	// verify that each target reaches the right handler
	cfg := configuration.DefaultConfiguration
	cfg.Authn.Provider.Type = "github"
	handler, err := forwardauth.New(5*time.Minute, &authz.Authorizer{Rules: cfg.Authz.Rules, Groups: cfg.Authz.Groups}, cfg.Storage)
	require.NoError(t, err)
	an, err := authn.New(t.Context(), cfg)
	require.NoError(t, err)

	healthz := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	hInt, hExt := New(cfg.Server, handler, an, observability.GetMetrics(), healthz, slog.New(slog.DiscardHandler))

	// internal

	// forward-auth
	req := httptest.NewRequest(http.MethodGet, "/", nil)
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

	// API
	req = httptest.NewRequest(http.MethodGet, "/api/sessions/list", nil)
	resp = httptest.NewRecorder()
	hExt.ServeHTTP(resp, req)
	require.Equal(t, http.StatusUnauthorized, resp.Code)
}
