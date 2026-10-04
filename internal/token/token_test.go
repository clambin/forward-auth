package token

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		time.Sleep(10 * time.Minute)
		token2, err := mgr.Validate(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, token, token2)

		// after access token expires, Validate() allocates a new token.
		time.Sleep(10 * time.Minute)
		token2, err = mgr.Validate(ctx, token)
		require.NoError(t, err)
		assert.NotEqual(t, token, token2)

		// both old and new refresh tokens exist in the Cache.
		refreshTokenCount, _ := mgr.Len(ctx)
		assert.Equal(t, 2, refreshTokenCount)

		// old refresh token expires
		time.Sleep(10 * time.Minute)
		refreshTokenCount, _ = mgr.Len(ctx)
		assert.Equal(t, 1, refreshTokenCount)

		// after refresh token expires, Validate() returns an error.
		time.Sleep(time.Hour + time.Minute)
		token2, err = mgr.Validate(ctx, token2)
		require.Error(t, err)
		assert.Nil(t, token2)
	})
}
