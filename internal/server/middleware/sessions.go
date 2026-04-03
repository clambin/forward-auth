package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/cache"
)

type contextKeyType struct{}

func SessionFromCtx(ctx context.Context) (SessionValidationResult, bool) {
	session, ok := ctx.Value(contextKeyType{}).(SessionValidationResult)
	return session, ok
}

type SessionValidationResult struct {
	Session *authn.Session
	Err     error
}

type Authenticator interface {
	Validate(ctx context.Context, sessionID string) (*authn.Session, error)
}

var _ Authenticator = (*authn.Authenticator)(nil)

// WithSessionValidation validates the session for a request using the provided cookie and adds the result to the request's context.
// When in strict mode, it will return a 401 if no valid session cookie is found.
func WithSessionValidation(cookieName string, authenticator Authenticator, strict bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var validationResult SessionValidationResult
			validationResult.Session, validationResult.Err = getSessionValidationResult(r, cookieName, authenticator)

			if strict && validationResult.Err != nil {
				if errors.Is(validationResult.Err, cache.ErrNotFound) {
					http.Error(w, "no valid session cookie found", http.StatusForbidden)
				} else {
					http.Error(w, "failed to validate session", http.StatusUnauthorized)
				}
				return
			}

			r = r.Clone(context.WithValue(r.Context(), contextKeyType{}, validationResult))
			next.ServeHTTP(w, r)
		})
	}
}

func getSessionValidationResult(r *http.Request, cookieName string, authenticator Authenticator) (*authn.Session, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, err
	}
	return authenticator.Validate(r.Context(), cookie.Value)
}
