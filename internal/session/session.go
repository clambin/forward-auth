package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	"codeberg.org/clambin/go-common/cache"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

const (
	namespaceKeyPrefix = "forward-auth"
	subsystemKeyPrefix = "session"
)

var (
	ErrSessionNotFound             = errors.New("session not found")
	ErrInvalidRefreshToken         = errors.New("invalid refresh token")
	ErrPreviousRefreshTokenExpired = errors.New("expired previous refresh token")
)

// A Session represents a user session on the server.
type Session struct {
	IssuedAt                 time.Time         `json:"issuedAt"`
	RotatedAt                time.Time         `json:"rotatedAt"`
	Identity                 provider.Identity `json:"identity"`
	ID                       string            `json:"id"`
	UserAgent                string            `json:"userAgent"`
	RefreshSecret            []byte            `json:"refreshSecret"`
	RefreshTokenHash         refreshTokenHash  `json:"refreshTokenHash"`
	PreviousRefreshTokenHash refreshTokenHash  `json:"previousRefreshTokenHash"`
}

// Sessions validates the session ID from the http request's session JWT against its data store.
// The session is refreshed each time the session JWT expires.  At this point, we generate a new refresh token.
// The previous refresh token is still accepted for a short grace period after rotation, so concurrent requests carrying the same
// expired JWT can all renew it.
type Sessions struct {
	store
	logger        *slog.Logger
	authenticator Authenticator
	cfg           configuration.ServerConfiguration
}

type Authenticator interface {
	InitiateLogin(ctx context.Context, url string) (string, error)
	ConfirmLogin(ctx context.Context, state string, code string) (provider.Identity, string, error)
}

func New(
	ttl time.Duration,
	serverConfiguration configuration.ServerConfiguration,
	storageConfiguration configuration.StorageConfiguration,
	authenticator Authenticator,
	logger *slog.Logger) (Sessions, error) {
	var store store
	switch strings.ToLower(storageConfiguration.Type) {
	case "local", "":
		store = &InMemoryStore{Cache: cache.New[string, Session](ttl, time.Minute)}
	case "redis":
		redisClient := redis.NewClient(&redis.Options{
			Addr:     storageConfiguration.Redis.Addr,
			Username: storageConfiguration.Redis.Username,
			Password: storageConfiguration.Redis.Password,
			DB:       storageConfiguration.Redis.DB,
		})
		store = &RedisStore{Client: redisClient, TTL: ttl}
	default:
		return Sessions{}, fmt.Errorf("invalid store type: %s", storageConfiguration.Type)
	}

	sessions := Sessions{
		store:         store,
		cfg:           serverConfiguration,
		authenticator: authenticator,
		logger:        logger,
	}
	return sessions, nil
}

// CreateSession creates a new session and returns a JWT token to be sent back to the client.
func (m Sessions) CreateSession(ctx context.Context, identity provider.Identity, r *http.Request) (Token, error) {
	// allocate a session ID
	sessionID := uuid.New().String()
	// create the session token that will be sent back to the client
	token := generateToken(sessionID, identity)
	// store a session in the data store
	var userAgent string
	if r != nil {
		userAgent = r.Header.Get("User-Agent")
	}
	now := time.Now()
	refreshSecret := generateRefreshToken()
	session := Session{
		ID:               sessionID,
		Identity:         identity,
		RefreshSecret:    refreshSecret[:],
		RefreshTokenHash: token.RefreshToken.hash(),
		IssuedAt:         now,
		UserAgent:        userAgent,
	}
	if err := m.put(ctx, token.Identity.Email, sessionID, session); err != nil {
		return token, err
	}
	return token, nil
}

// Validate validates that the session in the token exists in the store.  If required, it refreshes the token
// by rotating the refresh token. It returns the updated token.
func (m Sessions) Validate(ctx context.Context, token Token, r *http.Request) (Token, error) {
	// if the session doesn't exist, it's an error
	session, err := m.get(ctx, token.Identity.Email, token.SessionID)
	if err != nil {
		return token, err
	}

	// if the token has not expired and is still presenting the same refresh token, consider the token valid
	if !token.Expired() && token.RefreshToken.hash() == session.RefreshTokenHash {
		return token, nil
	}

	// either the token has expired, or the client is presenting a different refresh token (possibly the next rotated refresh token).
	// create a new token, rotating the refresh token.
	// rotateRefreshToken fails if the token's refresh token no longer matches the current or previous refresh token.

	token, session, err = m.rotateRefreshToken(token, session)
	if err != nil {
		return token, fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	// update the user agent in the store
	// trade-off: ideally, we'd update this (and a "last seen" timestamp) for each request. However,
	// concurrent requests could lead to one request rotating the refresh token and then
	// a second request writing back the old refresh token.
	if r != nil {
		session.UserAgent = r.Header.Get("User-Agent")
	}
	return token, m.update(ctx, token.Identity.Email, token.SessionID, session)
}

// rotateRefreshToken rotates the refresh token for a session. It returns the new token, session, and any error that occurred.
//
// In rotating the refresh token, we need to ensure that concurrent requests do not overwrite each other's changes.
// To protect against that, we keep track of the current refresh token and the previous refresh token.
// When we rotate, and we see that the client is presenting the previous refresh token, we accept it for a short
// period of time.
//
// Note that rotateRefreshToken does not update the session in the store. The caller does this
// so it can be done atomically with the token update.
func (m Sessions) rotateRefreshToken(token Token, session Session) (Token, Session, error) {
	// we'll need to issue a new token. update the ID
	token.ID = uuid.New().String()

	// check that the refresh token matches the current or previous refresh token
	now := time.Now()
	switch token.RefreshToken.hash() {
	case session.RefreshTokenHash:
		// current refresh token: rotate it
		token.RefreshToken = token.RefreshToken.next(session.RefreshSecret)
		session.PreviousRefreshTokenHash = session.RefreshTokenHash
		session.RefreshTokenHash = token.RefreshToken.hash()
		session.RotatedAt = now
	case session.PreviousRefreshTokenHash:
		// previous refresh token: the refresh token was already rotated by another request.
		// only accept it during the grace period after rotation.
		if now.Sub(session.RotatedAt) > refreshTokenGracePeriod {
			return Token{}, Session{}, ErrPreviousRefreshTokenExpired
		}
		// next() returns the same successor i.e., the current refresh token.
		token.RefreshToken = token.RefreshToken.next(session.RefreshSecret)
	default:
		return Token{}, Session{}, ErrInvalidRefreshToken
	}
	token.ExpiresAt = jwt.NewNumericDate(now.Add(tokenExpiration))
	return token, session, nil
}

func (m Sessions) DeleteSession(ctx context.Context, email string, sessionID string) error {
	return m.del(ctx, email, sessionID)
}

// LoginHandler returns an http.Handler that handles the login request and creates a new session
func (m Sessions) LoginHandler(logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// use state & code to validate the login and retrieve the user info
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			logger.Warn("rejecting login request: missing state or code")
			http.Error(w, "missing state or code", http.StatusBadRequest)
			return
		}

		logger.Debug("received valid login request")

		userInfo, redirectURL, err := m.authenticator.ConfirmLogin(r.Context(), state, code)
		if err != nil {
			logger.Warn("rejecting login request: failed to validate login", slog.Any("err", err))
			http.Error(w, "failed to validate login", http.StatusUnauthorized)
			return
		}

		ulog := logger.With(slog.String("user", userInfo.Email))
		ulog.Debug("user validated successfully")

		// create a new session & token for the new session
		tok, err := m.CreateSession(r.Context(), userInfo, r)
		if err != nil {
			ulog.Error("failed to create token", slog.Any("err", err))
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}
		ulog.Debug("session created", slog.String("session_id", tok.SessionID))

		signedToken, err := tok.Sign([]byte(m.cfg.Key))
		if err != nil {
			ulog.Error("failed to sign token", slog.Any("err", err))
			http.Error(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		setTokenCookie(w, m.cfg.CookieName, signedToken, m.cfg.Domain)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		ulog.Info("login successful")
	})
}

type identityKey struct{}

// Authenticator returns a middleware that validates the session cookie. If valid, it adds the identity
// to the request context and calls the next handler.
// If the token is invalid, redirectOnError determines whether to redirect to the login page or return an authentication error.
func (m Sessions) Authenticator(redirectOnError bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, err := m.authenticateRequest(w, r)
			if err == nil {
				next.ServeHTTP(w, SetAuthenticatedUser(r, identity))
				return
			}
			m.logger.Warn("failed to authenticate request", slog.Any("err", err))
			if !redirectOnError {
				http.Error(w, "failed to authenticate request", http.StatusUnauthorized)
				return
			}
			redirectURL, err := m.authenticator.InitiateLogin(r.Context(), r.URL.String())
			if err != nil {
				m.logger.Error("failed to initiate login", slog.Any("err", err))
				http.Error(w, "failed to initiate login", http.StatusInternalServerError)
				return
			}
			m.logger.Debug("redirecting to login page")
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		})
	}
}

// AuthenticatedUser returns the authenticated user from the request context.
func AuthenticatedUser(r *http.Request) (provider.Identity, bool) {
	id, ok := r.Context().Value(identityKey{}).(provider.Identity)
	return id, ok
}

// SetAuthenticatedUser sets the authenticated user in the request context.
func SetAuthenticatedUser(r *http.Request, identity provider.Identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, identity))
}

func (m Sessions) authenticateRequest(
	w http.ResponseWriter,
	r *http.Request,
) (provider.Identity, error) {
	// get the jwt token
	var token Token
	cookie, err := r.Cookie(m.cfg.CookieName)
	if err == nil {
		// parse the token
		token, err = ParseToken(cookie.Value, []byte(m.cfg.Key))
	}
	if err != nil {
		return provider.Identity{}, err
	}

	// validate the token
	newToken, err := m.Validate(r.Context(), token, r)
	switch {
	case errors.Is(err, ErrPreviousRefreshTokenExpired),
		errors.Is(err, ErrInvalidRefreshToken),
		errors.Is(err, ErrSessionNotFound):
		// we're rejecting the token and asking the user to login again. delete the old session.
		if err := m.DeleteSession(r.Context(), token.Identity.Email, token.SessionID); err != nil && !errors.Is(err, ErrSessionNotFound) {
			m.logger.Warn("failed to delete old session", slog.Any("err", err))
		}
		return provider.Identity{}, err
	case err != nil:
		return provider.Identity{}, err
	}
	// if the token was updated, sign the new token
	if newToken.ID != token.ID {
		m.logger.Debug("token updated")
		// we know the token can be signed because we created it in handleLogin()
		signedToken, _ := newToken.Sign([]byte(m.cfg.Key))
		// TODO: code smell: this is a side effect. move to the middleware?
		setTokenCookie(w, m.cfg.CookieName, signedToken, m.cfg.Domain)
	}

	return newToken.Identity, nil
}

// setTokenCookie adds a signed token cookie on the response.
func setTokenCookie(w http.ResponseWriter, cookieName, signedToken, domain string) {
	// Expires is empty, so the browser sends an expired cookie
	// which we may then attempt to refresh using the refresh token
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    signedToken,
		Domain:   domain,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
