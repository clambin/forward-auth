package token

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func TestParseToken(t *testing.T) {
	// valid signing key
	validKey := []byte("test_signing_key")

	// set up invalid test tokens
	wrongIssuer := NewToken(provider.Identity{Email: "foo@example.com"}, time.Hour, "refresh-token")
	wrongIssuer.Issuer = "wrong-issuer"
	noClaims := jwt.New(jwt.SigningMethodHS256)
	noClaimsSigned, _ := noClaims.SignedString(validKey)

	tests := []struct {
		name        string
		signedToken string
		wantErr     require.ErrorAssertionFunc
		wantExpired assert.BoolAssertionFunc
	}{
		{"valid", NewToken(provider.Identity{Email: "foo@example.com"}, time.Hour, "refresh-token").mustSign(validKey), require.NoError, assert.False},
		{"invalid signature", NewToken(provider.Identity{Email: "foo@example.com"}, time.Hour, "refresh-token").mustSign([]byte("invalid-key")), require.Error, assert.True},
		{"expired", NewToken(provider.Identity{Email: "foo@example.com"}, -time.Hour, "refresh-token").mustSign(validKey), require.NoError, assert.True},
		{"invalid issuer", wrongIssuer.mustSign(validKey), require.Error, assert.True},
		{"no claims", noClaimsSigned, require.Error, assert.True},
		{"missing subject", NewToken(provider.Identity{}, time.Hour, "refresh-token").mustSign(validKey), require.Error, assert.True},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseToken(tt.signedToken, validKey)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			tt.wantExpired(t, parsed.Expired())
		})
	}
}

func TestTokenManager_Validate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		mgr, err := NewTokenManager(time.Hour, configuration.StorageConfiguration{})
		require.NoError(t, err)

		// create a new token
		token, err := mgr.Token(ctx, provider.Identity{Email: "foo@example.com"})
		require.NoError(t, err)

		// token is valid
		token, err = mgr.Validate(ctx, token)
		require.NoError(t, err)

		// before access token expires, the token is valid and Validate() doesn't allocate a new token.
		time.Sleep(tokenExpirationDuration / 2)
		token2, err := mgr.Validate(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, token, token2)

		// after access token expires, Validate() allocates a new token.
		time.Sleep(tokenExpirationDuration)
		token2, err = mgr.Validate(ctx, token)
		require.NoError(t, err)
		assert.NotEqual(t, token, token2)

		// after refresh token expires, Validate() returns an error.
		time.Sleep(time.Hour + time.Minute)
		token2, err = mgr.Validate(ctx, token2)
		require.Error(t, err)
		assert.Nil(t, token2)
	})
}

func TestTokenStore(t *testing.T) {
	ctx := t.Context()
	c, err := tcredis.Run(ctx, "valkey/valkey:latest")
	require.NoError(t, err)
	endpoint, err := c.Endpoint(ctx, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	tests := []struct {
		name       string
		tokenStore tokenStore
	}{
		{
			name: "redis",
			tokenStore: &redisTokenStore{
				client: redis.NewClient(&redis.Options{Addr: endpoint}),
				ttl:    5 * time.Minute,
			},
		},
		{
			name: "memory",
			tokenStore: &inMemoryTokenStore{
				items: make(map[string]inMemoryTokenStoreItem),
				ttl:   5 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.tokenStore
			// create a refresh token and rotate it
			require.NoError(t, s.Set(ctx, "foo", RefreshTokenDetails{Generation: 1}))
			require.NoError(t, s.Rotate(ctx, "foo", "bar"))

			// verify the old refresh token is marked as rotated
			token, err := s.Get(ctx, "foo")
			require.NoError(t, err)
			assert.Equal(t, "bar", token.RotatedTo)

			// verify the new refresh token is created
			token, err = s.Get(ctx, "bar")
			require.NoError(t, err)
			assert.Equal(t, 2, token.Generation)
			assert.Empty(t, token.RotatedTo)

			// there should only be 1 active token
			count, err := s.Count(ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, count)

			// a rotated refresh token cannot be rotated again
			err = s.Rotate(ctx, "foo", "bar")
			require.ErrorIs(t, err, ErrRefreshTokenAlreadyRotated)

			// a non-existent refresh token cannot be rotated
			err = s.Rotate(ctx, "snafu", "bar")
			require.ErrorIs(t, err, ErrRefreshTokenNotFound)
		})
	}
}
