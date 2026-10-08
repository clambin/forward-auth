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
	c, err := tcredis.Run(ctx, "redis:latest")
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
			id := provider.Identity{Email: "foo@example.com", Name: "foo", Subject: "1234"}
			token, err := mgr.CreateSession(ctx, id, req)
			require.NoError(t, err)

			assert.Equal(t, id, token.Identity)
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
			found, err := mgr.store.Len(ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, found)

			// invalidate the refresh token
			token.RefreshToken = generateRefreshToken()
			_, err = mgr.Validate(ctx, token, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)

			// validate the store
			// TODO
			//session, err := mgr.Store.Get(ctx, "session:"+token.SessionID)
			//require.NoError(t, err)
			//assert.Equal(t, id, session.Identity)
		})
	}
}
