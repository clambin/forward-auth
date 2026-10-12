package forwardauth

import (
	"net/http"
	"strings"
	"testing"
	"time"
	"uuid"

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

			sess, err := newSessions(tt.ttl, tt.cfg)
			require.NoError(t, err)

			// create a session
			identity := provider.Identity{Email: "foo@example.com", Name: "foo", Subject: "1234"}
			token, err := sess.CreateSession(ctx, identity, req)
			require.NoError(t, err)

			assert.Equal(t, identity, token.Identity)
			assert.False(t, token.Expired())

			// expire the token
			token.ExpiresAt.Time = time.Now().Add(-1 * time.Minute)
			assert.True(t, token.Expired())

			// mgr should issue a new token
			oldToken := token
			token, err = sess.Validate(ctx, token, req)
			require.NoError(t, err)
			assert.Equal(t, "foo@example.com", token.Identity.Email)
			assert.False(t, token.Expired())
			assert.NotEqual(t, oldToken.RefreshToken, token.RefreshToken)

			// the previous refresh token is still accepted (e.g. concurrent requests) and yields the same refresh token
			concurrentToken, err := sess.Validate(ctx, oldToken, req)
			require.NoError(t, err)
			assert.False(t, concurrentToken.Expired())
			assert.Equal(t, token.RefreshToken, concurrentToken.RefreshToken)

			// renewing the current refresh token again rotates it
			token.ExpiresAt.Time = time.Now().Add(-1 * time.Minute)
			previousToken := token
			token, err = sess.Validate(ctx, token, req)
			require.NoError(t, err)
			assert.NotEqual(t, previousToken.RefreshToken, token.RefreshToken)

			// the previous refresh token is still accepted, but the one before that is not
			_, err = sess.Validate(ctx, previousToken, req)
			require.NoError(t, err)
			_, err = sess.Validate(ctx, oldToken, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)

			// once the grace period has passed, the previous refresh token is no longer accepted
			s, err := sess.get(ctx, token.Identity.Email, token.SessionID)
			require.NoError(t, err)
			s.RotatedAt = time.Now().Add(-refreshTokenGracePeriod - time.Second)
			require.NoError(t, sess.put(ctx, token.Identity.Email, token.SessionID, s))
			_, err = sess.Validate(ctx, previousToken, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)
			// the current refresh token is still accepted
			token, err = sess.Validate(ctx, token, req)
			require.NoError(t, err)

			// only 1 session should exist
			found, err := sess.Len(ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, found)

			// list the sessions
			sessions, err := sess.List(ctx, "foo@example.com")
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
			assert.NotZero(t, sessions[0].RotatedAt)

			// invalidate the token
			token.RefreshToken = generateRefreshToken()
			_, err = sess.Validate(ctx, token, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)

			// delete the session
			err = sess.DeleteSession(ctx, token.Identity.Email, token.SessionID)
			require.NoError(t, err)
			count, _ := sess.Len(t.Context())
			assert.Zero(t, count)

			// delete a non-existent session returns an error
			err = sess.DeleteSession(ctx, token.Identity.Email, token.SessionID)
			require.ErrorIs(t, err, ErrSessionNotFound)
		})
	}
}

func TestManager_InvalidStorage(t *testing.T) {
	_, err := newSessions(time.Hour, configuration.StorageConfiguration{Type: "invalid"})
	require.Error(t, err)
}

func FuzzManager_key(f *testing.F) {
	testCases := []string{"foo@example.com", "", "\"john:doe\"@example.com"}
	for _, tc := range testCases {
		f.Add(tc)
	}
	f.Fuzz(func(t *testing.T, email string) {
		sessionID := uuid.New().String()
		k := key(email, sessionID)
		require.NotEmpty(t, k)
		parts := strings.Split(k, ":")
		require.Len(t, parts, 4)
		assert.Equal(t, namespaceKeyPrefix, parts[0])
		assert.Equal(t, subsystemKeyPrefix, parts[1])
		assert.Equal(t, sessionID, parts[3])
	})
}
