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
	"uuid"

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
	RefreshToken RefreshToken      `json:"refreshToken"`
	Identity     provider.Identity `json:"identity"`
}

func (t tokenClaims) Expired() bool {
	return t.ExpiresAt == nil || t.ExpiresAt.Before(time.Now())
}

var _ slog.LogValuer = RefreshToken("")

type RefreshToken string

func (r RefreshToken) LogValue() slog.Value {
	if len(r) > 8 {
		return slog.StringValue(string(r[:3]) + "...")
	}
	return slog.StringValue("<REDACTED>")
}

var _ slog.LogValuer = (*Token)(nil)

type Token struct {
	tokenClaims
}

func (t Token) LogValue() slog.Value {
	return slog.StringValue(t.ID + "/" + t.Identity.Email)
}

func NewToken(id provider.Identity, accessTokenExpiration time.Duration, refreshToken RefreshToken) *Token {
	return &Token{
		ID:           uuid.New().String(),
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
}

type RefreshTokenDetails struct {
	IssuedAt          time.Time `json:"issuedAt"`
	provider.Identity `json:"identity"`
	RotatedTo         RefreshToken `json:"rotatedTo"`
	Generation        int          `json:"generation"`
}

func NewTokenManager(ttl time.Duration, cfg configuration.StorageConfiguration) (*Manager, error) {
	var store tokenStore
	switch cfg.Type {
	case "memory", "":
		store = &inMemoryTokenStore{
			items: make(map[RefreshToken]inMemoryTokenStoreItem),
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

	return &Manager{tokenStore: store}, nil
}

// Validate verifies that the received token is still valid.
// If the token is valid, it returns the token and no error.
// If the token is expired, but the refreshToken is still valid, it returns a new token, with a new refresh token.
//
// TODO: remove credential logging
func (m *Manager) Validate(ctx context.Context, token *Token, logger *slog.Logger) (*Token, error) {
	// if the jwt token is valid, return the current token.
	if !token.Expired() {
		return token, nil
	}

	// the jwt token has expired. attempt to rotate the refresh token.
	rotatedRefreshToken := generateRefreshToken()
	logger.Debug("token expired, attempting to rotate refresh token",
		slog.Any("from", token.RefreshToken),
		slog.Any("to", rotatedRefreshToken),
	)
	err := m.Rotate(ctx, token.RefreshToken, rotatedRefreshToken)
	switch {
	case err == nil:
		// fall through
	case errors.Is(err, ErrRefreshTokenAlreadyRotated):
		// the refresh token was already rotated by another request. attempt to find it
		rotatedRefreshToken, err = m.latestRefreshToken(ctx, token.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("latest refresh token: %w", err)
		}
		logger.Debug("latest refresh token found",
			slog.Any("refreshToken", rotatedRefreshToken),
		)
	default:
		return nil, fmt.Errorf("rotate: %w", err)
	}

	// generate a new refresh token and return a token based on that refresh token.
	logger.Debug("returning new JWT token",
		slog.Any("refreshToken", rotatedRefreshToken),
	)
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
func (m *Manager) latestRefreshToken(ctx context.Context, refreshToken RefreshToken) (RefreshToken, error) {
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

func generateRefreshToken() RefreshToken {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return RefreshToken(base64.StdEncoding.EncodeToString(b[:]))
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type tokenStore interface {
	Get(context.Context, RefreshToken) (RefreshTokenDetails, error)
	Set(context.Context, RefreshToken, RefreshTokenDetails) error
	Rotate(context.Context, RefreshToken, RefreshToken) error
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

func (r *redisTokenStore) Get(ctx context.Context, refreshToken RefreshToken) (RefreshTokenDetails, error) {
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

func (r *redisTokenStore) Set(ctx context.Context, refreshToken RefreshToken, details RefreshTokenDetails) error {
	value, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	err = r.client.Set(ctx, r.key(refreshToken), value, r.ttl).Err()
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

-- mark the old key as rotated. 
-- expire after 10 seconds to allow for concurrent requests
details.rotatedTo = ARGV[1]
redis.call("SET", KEYS[1], cjson.encode(details), "PX", 10000)

-- add the new key
details.rotatedTo = ""
details.generation = details.generation + 1
redis.call("SET", KEYS[2], cjson.encode(details), "PX", ttl)

return { "created" }
`)

func (r *redisTokenStore) Rotate(ctx context.Context, currentRefreshToken, rotatedRefreshToken RefreshToken) error {
	result, err := rotateScript.Run(ctx, r.client, []string{r.key(currentRefreshToken), r.key(rotatedRefreshToken)}, string(rotatedRefreshToken)).Result()
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

func (r *redisTokenStore) key(refreshToken RefreshToken) string {
	return refreshTokenPrefix + string(refreshToken)
}

type inMemoryTokenStoreItem struct {
	ttl     time.Time
	details RefreshTokenDetails
}

type inMemoryTokenStore struct {
	items map[RefreshToken]inMemoryTokenStoreItem
	ttl   time.Duration
	mu    sync.Mutex
}

func (i *inMemoryTokenStore) Get(_ context.Context, refreshToken RefreshToken) (RefreshTokenDetails, error) {
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

func (i *inMemoryTokenStore) Set(_ context.Context, refreshToken RefreshToken, details RefreshTokenDetails) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.items[refreshToken] = inMemoryTokenStoreItem{
		details: details,
		ttl:     time.Now().Add(i.ttl),
	}
	return nil
}

func (i *inMemoryTokenStore) Rotate(_ context.Context, oldRefreshToken, newRefreshToken RefreshToken) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	item, ok := i.items[oldRefreshToken]
	if !ok || time.Now().After(item.ttl) {
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
