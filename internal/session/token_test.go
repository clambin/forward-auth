package session

import (
	"encoding/json"
	"testing"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToken(t *testing.T) {
	const secret = "secret"
	// generate a token
	token := generateToken(provider.Identity{Email: "test@example.com"})

	// produce signed JWT token
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, token)
	raw, err := jwtToken.SignedString([]byte(secret))
	require.NoError(t, err)

	// verify the token
	token2, err := ParseToken(raw, []byte(secret))
	require.NoError(t, err)

	assert.Equal(t, token.SessionID, token2.SessionID)
	assert.Equal(t, token.Identity.Email, token2.Identity.Email)
	assert.Equal(t, token.RefreshToken, token2.RefreshToken)
	assert.Equal(t, token.ExpiresAt.Unix(), token2.ExpiresAt.Unix())
	assert.False(t, token2.Expired())
}

func TestRefreshTokenHash_JSON(t *testing.T) {
	refreshToken := generateRefreshToken()
	hash := refreshToken.hash()

	bytes, err := json.Marshal(hash)
	require.NoError(t, err)

	var read refreshTokenHash
	require.NoError(t, json.Unmarshal(bytes, &read))
	require.Equal(t, hash, read)
}
