package token

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
)

const (
	tokenIssuer             = "forward-auth"
	tokenExpirationDuration = 15 * time.Minute
	refreshTokenPrefix      = "refresh:"
)

var (
	ErrRefreshTokenNotFound       = errors.New("refresh token: not found")
	ErrRefreshTokenAlreadyRotated = errors.New("refresh token: already rotated")
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

type Manager struct {
	tokenStore
	logger *slog.Logger
}

type RefreshTokenDetails struct {
	IssuedAt          time.Time `json:"issuedAt"`
	provider.Identity `json:"identity"`
	RotatedTo         string `json:"rotatedTo"`
	Generation        int    `json:"generation"`
}

func NewTokenManager(ttl time.Duration, cfg configuration.StorageConfiguration, logger *slog.Logger) (*Manager, error) {
	var store tokenStore
	switch cfg.Type {
	case "memory", "":
		store = &inMemoryTokenStore{
			items: make(map[string]inMemoryTokenStoreItem),
			ttl:   ttl,
		}
	case "redis":
		store = &redisTokenStore{
			client: redis.NewClient(&redis.Options{
				Addr:     cfg.Redis.Addr,
				Username: cfg.Redis.Username,
				Password: cfg.Redis.Password,
				DB:       cfg.Redis.DB,
			}),
			ttl: ttl,
		}
	default:
		return nil, fmt.Errorf("invalid token manager configuration: unsupported storage type %s", cfg.Type)
	}

	return &Manager{tokenStore: store, logger: logger}, nil
}

// Validate verifies that the received token is still valid.
// If the token is valid, it returns the token and no error.
// If the token is expired, but the refreshToken is still valid, it returns a new token, with a new refresh token.
func (m *Manager) Validate(ctx context.Context, token *Token) (*Token, error) {
	// if the token is valid, return the current token.
	if !token.Expired() {
		return token, nil
	}

	// the token itself has expired. is there a valid refresh token?
	m.logger.Debug("token expired, checking refresh token", "refreshToken", token.RefreshToken)

	// the presented refresh token may have already been rotated.
	// follow the 'rotatedTo' chain until we find the current refresh token.
	// if any refresh token in the chain has already expired, t.latestRefreshToken() will return an error.
	refreshToken, err := m.latestRefreshToken(ctx, token.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("latest refresh token: %w", err)
	}

	m.logger.Debug("latest refresh token found", "refreshToken", refreshToken)

	// generate a new refresh token and return a token based on that refresh token.

	rotatedRefreshToken := generateRefreshToken()
	m.logger.Debug("attempting to rotate refresh token", "from", refreshToken, "to", rotatedRefreshToken)

	if err := m.Rotate(ctx, refreshToken, rotatedRefreshToken); err != nil {
		m.logger.Error("failed to rotate refresh token", "err", err)
		return nil, fmt.Errorf("rotate: %w", err)
	}
	return NewToken(token.Identity, tokenExpirationDuration, rotatedRefreshToken), nil
}

// Token returns a new token with a new refresh token for the given identity.
func (m *Manager) Token(ctx context.Context, id provider.Identity) (*Token, error) {
	refreshTokenID := generateRefreshToken()
	err := m.Set(ctx, refreshTokenID, RefreshTokenDetails{
		Identity:   id,
		IssuedAt:   time.Now(),
		Generation: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	return NewToken(id, tokenExpirationDuration, refreshTokenID), nil
}

// latestRefreshToken starts with a refresh token and, if rotated, follows the chain of refresh tokens
// until it finds the current (non-rotated) refresh token.
func (m *Manager) latestRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	for {
		details, err := m.Get(ctx, refreshToken)
		if err != nil {
			return "", err
		}
		if details.RotatedTo == "" {
			return refreshToken, nil
		}
		refreshToken = details.RotatedTo
	}
}

func generateRefreshToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type tokenStore interface {
	Get(context.Context, string) (RefreshTokenDetails, error)
	Set(context.Context, string, RefreshTokenDetails) error
	Rotate(context.Context, string, string) error
	Count(context.Context) (int, error)
}

var (
	_ tokenStore = (*redisTokenStore)(nil)
	_ tokenStore = (*inMemoryTokenStore)(nil)
)

type redisTokenStore struct {
	client *redis.Client
	ttl    time.Duration
}

func (r *redisTokenStore) Get(ctx context.Context, refreshToken string) (RefreshTokenDetails, error) {
	value, err := r.client.Get(ctx, r.key(refreshToken)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return RefreshTokenDetails{}, ErrRefreshTokenNotFound
		}
		return RefreshTokenDetails{}, fmt.Errorf("refresh token: %w", err)
	}
	var details RefreshTokenDetails
	err = json.Unmarshal([]byte(value), &details)
	if err != nil {
		return RefreshTokenDetails{}, fmt.Errorf("refresh token: %w", err)
	}
	return details, nil
}

func (r *redisTokenStore) Set(ctx context.Context, s string, details RefreshTokenDetails) error {
	value, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	err = r.client.Set(ctx, r.key(s), value, r.ttl).Err()
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	return nil
}

var rotateScript = redis.NewScript(`
local old = redis.call("GET", KEYS[1])
local ttl = redis.call("PTTL", KEYS[1])

if not old then
    return { "not found" }
end

local details = cjson.decode(old)

if details.rotatedTo ~= nil and details.rotatedTo ~= "" then
    return { "already rotated" }
end

-- mark the old key as rotated
details.rotatedTo = ARGV[1]
redis.call("SET", KEYS[1], cjson.encode(details), "PX", ttl)

-- add the new key
details.rotatedTo = ""
details.generation = details.generation + 1
redis.call("SET", KEYS[2], cjson.encode(details), "PX", ttl)

return { "created" }
`)

func (r *redisTokenStore) Rotate(ctx context.Context, currentRefreshToken, rotatedRefreshToken string) error {
	result, err := rotateScript.Run(ctx, r.client, []string{r.key(currentRefreshToken), r.key(rotatedRefreshToken)}, rotatedRefreshToken).Result()
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	values, ok := result.([]any)
	if !ok {
		return fmt.Errorf("refresh token: unexpected result type")
	}
	if len(values) != 1 {
		return fmt.Errorf("refresh token: unexpected result length")
	}
	value, ok := values[0].(string)
	if !ok {
		return fmt.Errorf("refresh token: unexpected result type")
	}
	switch value {
	case "created":
		return nil
	case "not found":
		return ErrRefreshTokenNotFound
	case "already rotated":
		return ErrRefreshTokenAlreadyRotated
	default:
		return fmt.Errorf("refresh token: %s", value)
	}
}

func (r *redisTokenStore) Count(ctx context.Context) (int, error) {
	var activeRefreshTokens int
	keys, _, err := r.client.Scan(ctx, 0, r.key("*"), 0).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: %w", err)
	}
	cmds := make([]*redis.StringCmd, len(keys))
	pipe := r.client.Pipeline()
	for i, key := range keys {
		cmds[i] = pipe.Get(ctx, key)
	}

	_, err = pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("redis: %w", err)
	}

	for _, cmd := range cmds {
		result, err := cmd.Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				// key expired between Scan & Get
				continue
			}
			return 0, fmt.Errorf("redis: %w", err)
		}
		var details RefreshTokenDetails
		if err = json.Unmarshal([]byte(result), &details); err == nil {
			if details.RotatedTo == "" {
				activeRefreshTokens++
			}
		}
	}

	return activeRefreshTokens, nil
}

func (r *redisTokenStore) key(refreshToken string) string {
	return refreshTokenPrefix + refreshToken
}

type inMemoryTokenStoreItem struct {
	ttl     time.Time
	details RefreshTokenDetails
}

type inMemoryTokenStore struct {
	items map[string]inMemoryTokenStoreItem
	ttl   time.Duration
	mu    sync.Mutex
}

func (i *inMemoryTokenStore) Get(_ context.Context, refreshToken string) (RefreshTokenDetails, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	item, ok := i.items[refreshToken]
	if !ok {
		return RefreshTokenDetails{}, ErrRefreshTokenNotFound
	}
	if item.ttl.Before(time.Now()) {
		delete(i.items, refreshToken)
		return RefreshTokenDetails{}, ErrRefreshTokenNotFound
	}
	return item.details, nil
}

func (i *inMemoryTokenStore) Set(_ context.Context, refreshToken string, details RefreshTokenDetails) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.items[refreshToken] = inMemoryTokenStoreItem{
		details: details,
		ttl:     time.Now().Add(i.ttl),
	}
	return nil
}

func (i *inMemoryTokenStore) Rotate(_ context.Context, oldRefreshToken string, newRefreshToken string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	item, ok := i.items[oldRefreshToken]
	if !ok {
		return ErrRefreshTokenNotFound
	}
	if item.details.RotatedTo != "" {
		return ErrRefreshTokenAlreadyRotated
	}
	item.details.RotatedTo = newRefreshToken
	i.items[oldRefreshToken] = item

	item.details.RotatedTo = ""
	item.details.Generation++
	i.items[newRefreshToken] = item
	return nil
}

func (i *inMemoryTokenStore) Count(_ context.Context) (int, error) {
	var activeRefreshTokens int
	i.mu.Lock()
	defer i.mu.Unlock()
	for k, v := range i.items {
		if v.ttl.Before(time.Now()) {
			delete(i.items, k)
			continue
		}
		if v.details.RotatedTo == "" {
			activeRefreshTokens++
		}
	}
	return activeRefreshTokens, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ prometheus.Collector = (*InstrumentedTokenManager)(nil)

type InstrumentedTokenManager struct {
	TokenManager *Manager
	Desc         *prometheus.Desc
}

func (i *InstrumentedTokenManager) Describe(ch chan<- *prometheus.Desc) {
	ch <- i.Desc
}

func (i *InstrumentedTokenManager) Collect(ch chan<- prometheus.Metric) {
	count, err := i.TokenManager.Count(context.Background())
	if err == nil {
		ch <- prometheus.MustNewConstMetric(i.Desc, prometheus.GaugeValue, float64(count))
	}
}
