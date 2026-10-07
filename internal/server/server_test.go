package server

/*
func TestServer(t *testing.T) {
	// verify that each target reaches the right handler
	cfg := configuration.DefaultConfiguration
	cfg.Authn.Provider.Type = "github"
	s, err := sessions.New(5*time.Minute, cfg.Storage)
	require.NoError(t, err)
	an, err := authn.New(t.Context(), cfg)
	require.NoError(t, err)
	az := authz.Authorizer{Rules: cfg.Authz.Rules, Groups: cfg.Authz.Groups}

	h := New(cfg.Server, s, an, &az, nil, middleware.GetMetrics(), slog.New(slog.DiscardHandler))

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
*/
