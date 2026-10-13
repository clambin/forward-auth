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
		currentToken, err := h.Validate(ctx, origToken, req)
		require.NoError(t, err)
		assert.Equal(t, origToken, currentToken)

		// when the token expires, but the session remains valid, the token is refreshed
		for range 3 {
			time.Sleep(20 * time.Minute)
			newToken, err := h.Validate(ctx, currentToken, req)
			require.NoError(t, err)
			assert.NotEqual(t, currentToken, newToken)
			currentToken = newToken
		}

		// when the session expired, the token is not refreshed
		time.Sleep(12 * time.Hour)
		_, err = h.Validate(ctx, currentToken, req)
		assert.ErrorIs(t, err, forwardauth.ErrSessionNotFound)
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
	_, err = h.Validate(ctx, token, req)
	require.NoError(t, err)

	// delete the session
	err = h.DeleteSession(ctx, token.Identity.Email, token.SessionID)
	require.NoError(t, err)

	// validation should now fail, even if the token is still valid
	_, err = h.Validate(ctx, token, req)
	require.ErrorIs(t, err, forwardauth.ErrSessionNotFound)
}

func TestHandler_Authorize(t *testing.T) {
	tests := []struct {
		name  string
		token bool
		allow bool
		want  error
	}{
		{"allow", true, true, nil},
		{"forbid", true, false, forwardauth.ErrNotAllowed},
		{"no token", false, false, forwardauth.ErrSessionNotFound},
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

			_, err = h.Validate(ctx, token, req)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestOriginalRequest(t *testing.T) {
	type want struct {
		method string
		path   string
	}
	tests := []struct {
		name    string
		headers map[string]string
		want    want
	}{
		{
			name:    "basic",
			headers: map[string]string{"X-Forwarded-Uri": "/", "X-Forwarded-Host": "example.com"},
			want:    want{http.MethodGet, "https://example.com/"},
		},
		{
			name:    "method",
			headers: map[string]string{"X-Forwarded-Method": http.MethodPost, "X-Forwarded-Uri": "/", "X-Forwarded-Host": "example.com"},
			want:    want{http.MethodPost, "https://example.com/"},
		},
		{
			name:    "encoded path",
			headers: map[string]string{"X-Forwarded-Uri": "/files/a%2Fb", "X-Forwarded-Host": "example.com"},
			want:    want{http.MethodGet, "https://example.com/files/a%2Fb"},
		},
		{
			name:    "arguments",
			headers: map[string]string{"X-Forwarded-Uri": "/?arg=true", "X-Forwarded-Host": "example.com"},
			want:    want{http.MethodGet, "https://example.com/?arg=true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			method, path, err := forwardauth.OriginalRequest(req)
			require.NoError(t, err)
			assert.Equal(t, tt.want.method, method)
			assert.Equal(t, tt.want.path, path.String())
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
