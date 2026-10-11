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

// TestServer only tests if all the routes reach the right handler
func TestServer(t *testing.T) {
	// verify that each target reaches the right handler
	cfg := configuration.DefaultConfiguration
	cfg.Authn.Provider.Type = "github"
	s, err := session.New(5*time.Minute, cfg.Storage)
	require.NoError(t, err)
	an, err := authn.New(t.Context(), cfg)
	require.NoError(t, err)
	az := authz.Authorizer{Rules: cfg.Authz.Rules, Groups: cfg.Authz.Groups}

	h := New(cfg.Server, s, an, &az, nil, observability.GetMetrics(), slog.New(slog.DiscardHandler))

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
	require.Equal(t, http.StatusForbidden, resp.Code)
}
