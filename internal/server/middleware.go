package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/clambin/forward-auth/internal/forwardauth"
)

var ErrTokenExpired = errors.New("token expired")

type tokenCtx struct{}
type parsedToken struct {
	err   error
	token forwardauth.Token
}

type tokenMode int

const (
	strictTokenMode tokenMode = iota
	laxTokenMode
)

// withForwardAuthToken parses the JWT Token from a request and adds it to the request's context.
// It can operate in strict mode, rejecting a request that doesn't present a valid token,
// or in lax mode, allowing the request to continue even if the token is invalid.
func withForwardAuthToken(cookieName string, secret []byte, mode tokenMode) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the cookie from the request
			var tok parsedToken
			tok.token, tok.err = tokenFromCookie(r, cookieName, secret)
			if tok.err == nil && tok.token.Expired() {
				tok.err = ErrTokenExpired
			}
			// in strict mode, reject the request if the token is invalid
			if tok.err != nil && mode == strictTokenMode {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			// add the token to the request context
			ctx := context.WithValue(r.Context(), tokenCtx{}, tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func tokenFromRequest(r *http.Request) (forwardauth.Token, error) {
	tok, ok := r.Context().Value(tokenCtx{}).(parsedToken)
	if !ok {
		return forwardauth.Token{}, http.ErrNoCookie
	}
	return tok.token, tok.err
}

func tokenFromCookie(r *http.Request, cookieName string, key []byte) (forwardauth.Token, error) {
	// get the jwt token
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return forwardauth.Token{}, err
	}
	// parse the token
	return forwardauth.ParseToken(cookie.Value, key)
}
