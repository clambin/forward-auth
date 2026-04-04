package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/cache"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessions(t *testing.T) {
	m, err := New(time.Minute, configuration.StorageConfiguration{})
	require.NoError(t, err)
	ctx := t.Context()

	// session should not exist
	_, err = m.Get(ctx, "invalid")
	require.ErrorIs(t, err, cache.ErrNotFound)

	// add a session
	id, err := m.Add(ctx, provider.UserInfo{Email: "foo@example.com"})
	require.NoError(t, err)
	assert.NotZero(t, id)

	// session should exist
	session, err := m.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", session.UserInfo.Email)

	// list sessions
	sessions, err := m.List(ctx)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)

	// delete the session
	err = m.Delete(ctx, id)
	require.NoError(t, err)

	// session should not exist
	_, err = m.Get(ctx, id)
	require.ErrorIs(t, err, cache.ErrNotFound)
}

func TestSessions_Middleware(t *testing.T) {
	tests := []struct {
		name           string
		strict         bool
		setCookie      bool
		wantStatusCode int
		wantSession    require.BoolAssertionFunc
	}{
		{"strict - no cookie", true, false, http.StatusUnauthorized, require.False},
		{"strict - cookie", true, true, http.StatusOK, require.True},
		{"lax - no cookie", false, false, http.StatusForbidden, require.False},
		{"lax - cookie", false, true, http.StatusOK, require.True},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cookieName = "session"
			m, err := New(5*time.Minute, configuration.StorageConfiguration{})
			require.NoError(t, err)

			h := m.Middleware(cookieName, tt.strict)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _, ok := SessionFromCtx(r.Context())
				tt.wantSession(t, ok)
				if !ok {
					http.Error(w, "no valid session cookie found", http.StatusForbidden)
				}
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.setCookie {
				id, _ := m.Add(t.Context(), provider.UserInfo{Email: "foo@example.com"})
				req.AddCookie(&http.Cookie{Name: cookieName, Value: id})
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, tt.wantStatusCode, resp.Code)
		})
	}
}
