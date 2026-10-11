package session

import (
	"net/http"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestManager(t *testing.T) {
	ctx := t.Context()
	c, err := tcredis.Run(ctx, "ghcr.io/valkey-io/valkey:latest")
	require.NoError(t, err)
	endpoint, err := c.Endpoint(ctx, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	tests := []struct {
		name string
		ttl  time.Duration
		cfg  configuration.StorageConfiguration
	}{
		{"redis", 5 * time.Minute, configuration.StorageConfiguration{Type: "redis", Redis: configuration.StorageRedisConfiguration{Addr: endpoint}}},
		{"memory", 5 * time.Minute, configuration.StorageConfiguration{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", "test")

			mgr, err := New(tt.ttl, tt.cfg)
			require.NoError(t, err)

			// create a session
			identity := provider.Identity{Email: "foo@example.com", Name: "foo", Subject: "1234"}
			token, err := mgr.CreateSession(ctx, identity, req)
			require.NoError(t, err)

			assert.Equal(t, identity, token.Identity)
			assert.False(t, token.Expired())

			// expire the token
			token.ExpiresAt.Time = time.Now().Add(-1 * time.Minute)
			assert.True(t, token.Expired())

			// mgr should issue a new token
			token, err = mgr.Validate(ctx, token, req)
			require.NoError(t, err)
			assert.Equal(t, "foo@example.com", token.Identity.Email)
			assert.False(t, token.Expired())

			// only 1 session should exist
			found, err := mgr.Len(ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, found)

			// list the sessions
			sessions, err := mgr.List(ctx, "foo@example.com")
			require.NoError(t, err)
			require.Len(t, sessions, 1)
			// token is linked to the right session
			assert.Equal(t, token.SessionID, sessions[0].ID)
			// token is for the right user
			assert.Equal(t, "foo@example.com", sessions[0].Identity.Email)
			// session refresh token hash matches the token's refresh token
			assert.Equal(t, token.RefreshToken.hash(), sessions[0].RefreshTokenHash)
			// session captures the right user agent
			assert.Equal(t, "test", sessions[0].UserAgent)
			// timestamps are filled in
			assert.NotZero(t, sessions[0].IssuedAt)
			assert.NotZero(t, sessions[0].LastSeen)

			// invalidate the token
			token.RefreshToken = generateRefreshToken()
			_, err = mgr.Validate(ctx, token, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)

			// delete the session
			err = mgr.Delete(ctx, token.Identity.Email, token.SessionID)
			require.NoError(t, err)
			count, _ := mgr.Len(t.Context())
			assert.Zero(t, count)

			// delete a non-existent session returns an error
			err = mgr.Delete(ctx, token.Identity.Email, token.SessionID)
			require.ErrorIs(t, err, ErrSessionNotFound)
		})
	}
}
