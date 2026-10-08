package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	"uuid"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/golang-jwt/jwt/v5"
)

const (
	refreshTokenByteSize = 32 // 256 bytes
	tokenExpiration      = 15 * time.Minute
	tokenIssuer          = "forward-auth"
)

type RefreshToken [refreshTokenByteSize]byte

func generateRefreshToken() RefreshToken {
	var b [refreshTokenByteSize]byte
	_, _ = rand.Read(b[:])
	return b
}

func (t RefreshToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(t[:]))
}

func (t *RefreshToken) UnmarshalJSON(b []byte) error {
	var encoded string
	if err := json.Unmarshal(b, &encoded); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err == nil {
		copy(t[:], decoded)
	}
	return err
}

func (t RefreshToken) hash() refreshTokenHash {
	return refreshTokenHash(sha256.New().Sum(t[:]))
}

type refreshTokenHash [sha256.Size]byte

func (h refreshTokenHash) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(h[:]))
}

func (h *refreshTokenHash) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		copy(h[:], raw)
	}
	return err
}

type Token struct {
	jwt.RegisteredClaims
	SessionID    string            `json:"sessionID"`
	RefreshToken RefreshToken      `json:"refreshToken"` // TODO: as RefreshToken?
	Identity     provider.Identity `json:"identity"`
}

func generateToken(id provider.Identity) Token {
	return Token{
		Issuer:       tokenIssuer,
		IssuedAt:     &jwt.NumericDate{Time: time.Now()},
		ExpiresAt:    &jwt.NumericDate{Time: time.Now().Add(tokenExpiration)},
		SessionID:    uuid.New().String(),
		RefreshToken: generateRefreshToken(),
		Identity:     id,
	}
}

func ParseToken(rawToken string, signingKey []byte) (Token, error) {
	signFunc := func(token *jwt.Token) (any, error) {
		return signingKey, nil
	}

	jwtToken, err := jwt.ParseWithClaims(rawToken, &Token{}, signFunc,
		jwt.WithoutClaimsValidation(),                                // we want to check expiration ourselves
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), // simplifies signFunc
	)
	if err != nil {
		return Token{}, fmt.Errorf("jwt: %w", err)
	}
	if jwtToken == nil || jwtToken.Claims == nil {
		return Token{}, fmt.Errorf("jwt token is nil or has no valid claims")
	}
	token := *jwtToken.Claims.(*Token)

	// these aren't really necessary. Issuer is easily spoofed and Subject will be validated against the Store anyway.
	if token.Issuer != tokenIssuer {
		return Token{}, fmt.Errorf("jwt issuer is not %s", tokenIssuer)
	}
	if token.Identity.Email == "" {
		return Token{}, fmt.Errorf("jwt identity email is empty")
	}
	return token, nil
}

func (t Token) Expired() bool {
	return time.Now().After(t.ExpiresAt.Time)
}

func (t Token) Sign(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, t).SignedString(key)
}
