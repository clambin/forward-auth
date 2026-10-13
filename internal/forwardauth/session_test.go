package forwardauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestSessions(t *testing.T) {
	ctx := t.Context()
	c, err := tcredis.Run(ctx, "redis:8.10.2")
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

			sessions, err := newSessions(tt.ttl, tt.cfg)
			require.NoError(t, err)

			// create a session
			identity := provider.Identity{Email: "foo@example.com", Name: "foo", Subject: "1234"}
			token, err := sessions.CreateSession(ctx, identity, req)
			require.NoError(t, err)

			assert.Equal(t, identity, token.Identity)
			assert.False(t, token.Expired())

			// expire the token
			token.ExpiresAt.Time = time.Now().Add(-1 * time.Minute)
			assert.True(t, token.Expired())

			// mgr should issue a new token
			oldToken := token
			token, err = sessions.validateToken(ctx, token, req)
			require.NoError(t, err)
			assert.Equal(t, "foo@example.com", token.Identity.Email)
			assert.False(t, token.Expired())
			assert.NotEqual(t, oldToken.RefreshToken, token.RefreshToken)

			// the previous refresh token is still accepted (e.g. concurrent requests) and yields the same refresh token
			concurrentToken, err := sessions.validateToken(ctx, oldToken, req)
			require.NoError(t, err)
			assert.False(t, concurrentToken.Expired())
			assert.Equal(t, token.RefreshToken, concurrentToken.RefreshToken)

			// renewing the current refresh token again rotates it
			token.ExpiresAt.Time = time.Now().Add(-1 * time.Minute)
			previousToken := token
			token, err = sessions.validateToken(ctx, token, req)
			require.NoError(t, err)
			assert.NotEqual(t, previousToken.RefreshToken, token.RefreshToken)

			// the previous refresh token is still accepted, but the one before that is not
			_, err = sessions.validateToken(ctx, previousToken, req)
			require.NoError(t, err)
			_, err = sessions.validateToken(ctx, oldToken, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)

			// once the grace period has passed, the previous refresh token is no longer accepted
			s, err := sessions.get(ctx, token.Identity.Email, token.SessionID)
			require.NoError(t, err)
			s.RotatedAt = time.Now().Add(-refreshTokenGracePeriod - time.Second)
			require.NoError(t, sessions.put(ctx, token.Identity.Email, token.SessionID, s))
			_, err = sessions.validateToken(ctx, previousToken, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)
			// the current refresh token is still accepted
			token, err = sessions.validateToken(ctx, token, req)
			require.NoError(t, err)

			// only 1 session should exist
			found, err := sessions.Len(ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, found)

			// list the sessions
			activeSessions, err := sessions.List(ctx, "foo@example.com")
			require.NoError(t, err)
			require.Len(t, activeSessions, 1)
			// token is linked to the right session
			assert.Equal(t, token.SessionID, activeSessions[0].ID)
			// token is for the right user
			assert.Equal(t, "foo@example.com", activeSessions[0].Identity.Email)
			// session refresh token hash matches the token's refresh token
			assert.Equal(t, token.RefreshToken.hash(), activeSessions[0].RefreshTokenHash)
			// session captures the right user agent
			assert.Equal(t, "test", activeSessions[0].UserAgent)
			// timestamps are filled in
			assert.NotZero(t, activeSessions[0].IssuedAt)
			assert.NotZero(t, activeSessions[0].RotatedAt)

			// invalidate the token
			token.RefreshToken = generateRefreshToken()
			_, err = sessions.validateToken(ctx, token, req)
			require.ErrorIs(t, err, ErrInvalidRefreshToken)

			// delete the session
			err = sessions.DeleteSession(ctx, token.Identity.Email, token.SessionID)
			require.NoError(t, err)
			count, _ := sessions.Len(t.Context())
			assert.Zero(t, count)

			// delete a non-existent session returns an error
			err = sessions.DeleteSession(ctx, token.Identity.Email, token.SessionID)
			require.ErrorIs(t, err, ErrSessionNotFound)
		})
	}
}

func TestSessions_InvalidStorage(t *testing.T) {
	_, err := newSessions(time.Hour, configuration.StorageConfiguration{Type: "invalid"})
	require.Error(t, err)
}

// TestSessions_Decode verifies that the session format doesn't change in the session store.
func TestSessions_Decode(t *testing.T) {
	var secret [32]byte
	session := Session{
		IssuedAt:                 time.Date(2026, time.October, 13, 0, 0, 0, 0, time.UTC),
		RotatedAt:                time.Date(2026, time.October, 13, 0, 15, 0, 0, time.UTC),
		Identity:                 provider.Identity{Email: "foo@example.com"},
		ID:                       "my-fake-id",
		UserAgent:                "my-user-agent",
		RefreshSecret:            secret[:],
		RefreshTokenHash:         refreshTokenHash{},
		PreviousRefreshTokenHash: refreshTokenHash{},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(&session))
	want := `{
  "issuedAt": "2026-10-13T00:00:00Z",
  "rotatedAt": "2026-10-13T00:15:00Z",
  "identity": {
    "sub": "",
    "email": "foo@example.com",
    "name": ""
  },
  "id": "my-fake-id",
  "userAgent": "my-user-agent",
  "refreshSecret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "refreshTokenHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "previousRefreshTokenHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
`
	require.Equal(t, want, buf.String())
}
