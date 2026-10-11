package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToken(t *testing.T) {
	const secret = "secret"
	// generate a token
	token := generateToken("my-session-id", provider.Identity{Email: "test@example.com"})

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

func TestRefreshToken_hash(t *testing.T) {
	refreshToken := RefreshToken(bytes.Repeat([]byte{0}, 32)) //generateRefreshToken()
	want := refreshTokenHash(sha256.Sum256(refreshToken[:]))

	assert.Equal(t, want, refreshToken.hash())
	assert.Equal(t, "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925", hex.EncodeToString(want[:]))
}

func TestToken_Expired(t *testing.T) {
	tests := []struct {
		name    string
		token   Token
		expired assert.BoolAssertionFunc
	}{
		{"valid", Token{ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(time.Hour)}}, assert.False},
		{"expired", Token{ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(-time.Hour)}}, assert.True},
		{"null", Token{}, assert.True},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.expired(t, tt.token.Expired())
		})
	}
}
