package token

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/cache"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenIssuer                 = "forward-auth"
	tokenExpirationDuration     = 15 * time.Minute
	refreshTokenSundownDuration = 15 * time.Minute
)

type tokenClaims struct {
	jwt.RegisteredClaims
	RefreshToken string            `json:"refreshToken"`
	Identity     provider.Identity `json:"identity"`
}

func (t tokenClaims) Expired() bool {
	return t.ExpiresAt == nil || t.ExpiresAt.Before(time.Now())
}

type Token struct {
	tokenClaims
}

func NewToken(id provider.Identity, accessTokenExpiration time.Duration, refreshToken string) *Token {
	return &Token{
		Issuer:       tokenIssuer,
		ExpiresAt:    jwt.NewNumericDate(time.Now().Add(accessTokenExpiration)),
		RefreshToken: refreshToken,
		Identity:     id,
	}
}

func ParseToken(raw string, key []byte) (*Token, error) {
	signFunc := func(token *jwt.Token) (any, error) {
		return key, nil
	}

	jwtToken, err := jwt.ParseWithClaims(raw, &tokenClaims{}, signFunc,
		jwt.WithoutClaimsValidation(),                                // we want to check expiration ourselves
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), // simplifies signFunc
	)
	if err != nil {
		return nil, err
	}

	claims, ok := jwtToken.Claims.(*tokenClaims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("jwt has no valid claims")
	}
	if claims.Issuer != tokenIssuer {
		return nil, fmt.Errorf("jwt issuer is not %s", tokenIssuer)
	}
	if claims.Identity.Email == "" {
		return nil, fmt.Errorf("jwt identity subject is empty")
	}
	return &Token{tokenClaims: *claims}, nil
}

func (t Token) Sign(key []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, t.tokenClaims)
	return token.SignedString(key)
}

func (t Token) mustSign(key []byte) string {
	signed, err := t.Sign(key)
	if err != nil {
		panic(err)
	}
	return signed
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type TokenManager struct {
	cache.Cache[RefreshTokenDetails] // or just the refreshToken?
}

type RefreshTokenDetails struct {
	provider.Identity `json:"identity"`
	IssuedAt          time.Time `json:"issuedAt"`
	Generation        int       `json:"generation"`
}

func NewTokenManager(ttl time.Duration, cfg configuration.StorageConfiguration) (*TokenManager, error) {
	c, err := cache.New[RefreshTokenDetails](ttl, "refresh", cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid token manager configuration: %w", err)
	}

	return &TokenManager{Cache: c}, nil
}

// Validate verifies that the received token is still valid.
// If the token is valid, it returns the token and no error.
// If the token is expired, but the refreshToken is still valid, it returns a new token, with a new refresh token.
func (t *TokenManager) Validate(ctx context.Context, token *Token) (*Token, error) {
	// if the token is valid, return the current token.
	if !token.Expired() {
		return token, nil
	}

	// the token itself has expired. if the refresh token is also expired, return an error.
	currentRefreshTokenDetails, err := t.Get(ctx, token.RefreshToken)
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			return nil, fmt.Errorf("refresh token not found or expired")
		}
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	// check that the refreshToken is associated with the current user
	// TODO: this should always be the case
	if currentRefreshTokenDetails.Email != token.Identity.Email {
		return nil, fmt.Errorf("refresh token not associated with current user")
	}

	// Right now, we expire the old token after a couple of seconds to allow for concurrent requests.
	// This does generate multiple refresh tokens (one for each concurrent request) that only expire
	// after the session TTL.
	// Probably needs a distributed lock to prevent multiple refresh tokens from being created.

	newToken, err := t.cycleToken(ctx, token.Identity, currentRefreshTokenDetails.Generation+1)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	// expire the old refreshToken after a couple of seconds to handle any concurrent requests
	err = t.Expire(ctx, token.RefreshToken, refreshTokenSundownDuration)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	return newToken, nil
}

// Token returns a new token with a new refresh token for the given identity.
func (t *TokenManager) Token(ctx context.Context, id provider.Identity) (*Token, error) {
	return t.cycleToken(ctx, id, 1)
}

func (t *TokenManager) cycleToken(ctx context.Context, id provider.Identity, generation int) (*Token, error) {
	refreshTokenID := generateRefreshToken()
	err := t.Set(ctx, refreshTokenID, RefreshTokenDetails{
		Identity:   id,
		IssuedAt:   time.Now(),
		Generation: generation,
	})
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	return NewToken(id, tokenExpirationDuration, refreshTokenID), nil
}

func generateRefreshToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}
