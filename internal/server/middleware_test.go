package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/forwardauth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithToken_Lax(t *testing.T) {
	const cookieName = "token"
	var validKey = []byte("secret")
	tests := []struct {
		name      string
		tokenFunc func() string
		err       error
	}{
		{
			name: "no token",
			err:  http.ErrNoCookie,
		},
		{
			name: "invalid token",
			tokenFunc: func() string {
				return "invalid"
			},
			err: jwt.ErrTokenMalformed,
		},
		{
			name: "wrong signature",
			tokenFunc: func() string {
				var tok forwardauth.Token
				rawToken, _ := tok.Sign([]byte("invalid-key"))
				return rawToken
			},
			err: jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "expired token",
			tokenFunc: func() string {
				tok := forwardauth.Token{
					Issuer:    "forward-auth",
					Identity:  provider.Identity{Email: "test@example.com"},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
				}
				rawToken, _ := tok.Sign(validKey)
				return rawToken
			},
			err: ErrTokenExpired,
		},

		{
			name: "valid token",
			tokenFunc: func() string {
				tok := forwardauth.Token{
					Issuer:    "forward-auth",
					Identity:  provider.Identity{Email: "test@example.com"},
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}
				rawToken, _ := tok.Sign(validKey)
				return rawToken
			},
			err: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := withForwardAuthToken(cookieName, validKey, laxTokenMode)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := tokenFromRequest(r)
				require.ErrorIs(t, err, tt.err)
			}))

			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.tokenFunc != nil {
				req.AddCookie(&http.Cookie{
					Name:  cookieName,
					Value: tt.tokenFunc(),
				})
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, http.StatusOK, resp.Code)
		})
	}
}
