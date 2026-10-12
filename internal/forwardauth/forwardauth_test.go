package forwardauth_test

import (
	"net/http"
	"net/url"
	"testing"
	"testing/synctest"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/forwardauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandler_Refresh tests that the token is refreshed when it expires, until the session expires.
func TestHandler_Refresh(t *testing.T) {
	ctx := t.Context()
	h, err := forwardauth.New(6*time.Hour, &fakeAuthorizer{allow: true}, configuration.StorageConfiguration{})
	require.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "foo")
	req.Header.Set("X-Forwarded-Uri", "/?mode=refresh")

	synctest.Test(t, func(t *testing.T) {
		// create a new session
		origToken, err := h.CreateSession(ctx, provider.Identity{Email: "foo@example.com"}, req)
		require.NoError(t, err)

		// while the token doesn't expire, the session remains valid
		result, currentToken, err := h.Validate(ctx, origToken, req)
		require.NoError(t, err)
		assert.Equal(t, origToken, currentToken)
		assert.Equal(t, forwardauth.Allowed, result)

		// when the token expires, but the session remains valid, the token is refreshed
		for range 3 {
			time.Sleep(20 * time.Minute)
			result, newToken, err := h.Validate(ctx, currentToken, req)
			require.NoError(t, err)
			assert.NotEqual(t, currentToken, newToken)
			assert.Equal(t, forwardauth.Allowed, result)
			currentToken = newToken
		}

		// when the session expired, the token is not refreshed
		time.Sleep(12 * time.Hour)
		result, _, err = h.Validate(ctx, currentToken, req)
		require.NoError(t, err)
		assert.Equal(t, forwardauth.NotAuthenticated, result)
	})
}

func TestHandler_DeleteSession(t *testing.T) {
	ctx := t.Context()
	h, err := forwardauth.New(6*time.Hour, &fakeAuthorizer{allow: true}, configuration.StorageConfiguration{})
	require.NoError(t, err)
	req, _ := http.NewRequest(http.MethodGet, "/?mode=refresh", nil)
	req.Header.Set("User-Agent", "foo")

	// create a new session
	token, err := h.CreateSession(ctx, provider.Identity{Email: "foo@example.com"}, req)
	require.NoError(t, err)

	// validate the token & session
	result, _, err := h.Validate(ctx, token, req)
	require.NoError(t, err)
	require.Equal(t, forwardauth.Allowed, result)

	// delete the session
	err = h.DeleteSession(ctx, token.Identity.Email, token.SessionID)
	require.NoError(t, err)

	// validation should now fail, even if the token is still valid
	result, _, err = h.Validate(ctx, token, req)
	require.NoError(t, err)
	require.Equal(t, forwardauth.NotAuthenticated, result)
}

func TestHandler_Authorize(t *testing.T) {
	tests := []struct {
		name  string
		token bool
		allow bool
		want  forwardauth.Result
	}{
		{"allow", true, true, forwardauth.Allowed},
		{"forbid", true, false, forwardauth.Forbidden},
		{"no token", false, false, forwardauth.NotAuthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			h, err := forwardauth.New(6*time.Hour, &fakeAuthorizer{allow: tt.allow}, configuration.StorageConfiguration{})
			require.NoError(t, err)
			req, _ := http.NewRequest(http.MethodGet, "/?mode=refresh", nil)
			req.Header.Set("User-Agent", "foo")

			var token forwardauth.Token
			if tt.token {
				token, err = h.CreateSession(ctx, provider.Identity{Email: "foo@example.com"}, req)
				require.NoError(t, err)
			}

			result, _, err := h.Validate(ctx, token, req)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result)
		})
	}
}

var _ forwardauth.Authorizer = &fakeAuthorizer{}

type fakeAuthorizer struct{ allow bool }

func (f fakeAuthorizer) Allow(_ *url.URL, _ string) bool {
	return f.allow
}

func (f fakeAuthorizer) GroupsForUser(_ string) []string {
	// not needed here
	panic("never reached during testing")
}
