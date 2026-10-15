package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/forwardauth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithToken(t *testing.T) {
	h, err := forwardauth.New(time.Hour, &fakeAuthorizer{allow: true}, configuration.StorageConfiguration{})
	require.NoError(t, err)

	const cookieName = "token"
	var validKey = []byte("secret")
	tests := []struct {
		name       string
		tokenFunc  generateTokenFunc
		err        error
		statusCode int
	}{
		{
			name:       "no token",
			err:        http.ErrNoCookie,
			statusCode: http.StatusSeeOther,
		},
		{
			name: "invalid token",
			tokenFunc: func(tb testing.TB, h *forwardauth.Handler, req *http.Request) string {
				return "invalid"
			},
			err:        jwt.ErrTokenMalformed,
			statusCode: http.StatusSeeOther,
		},
		{
			name:       "wrong signature",
			tokenFunc:  generateToken([]byte("invalid-key"), time.Hour),
			err:        jwt.ErrTokenSignatureInvalid,
			statusCode: http.StatusSeeOther,
		},
		{
			name:       "valid token",
			tokenFunc:  generateToken(validKey, time.Hour),
			err:        nil,
			statusCode: http.StatusOK,
		},
		{
			name:       "expired token",
			tokenFunc:  generateToken(validKey, -time.Hour),
			err:        nil, // forwardauth.Handler has successfully rotated the expired token
			statusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.ServerConfiguration{
				CookieName: cookieName,
				Key:        string(validKey),
				Domain:     ".example.com",
			}
			s := withForwardAuthToken(cfg, h, &fakeAuthenticator{}, slog.New(slog.DiscardHandler))(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err := tokenFromRequest(r)
					require.ErrorIs(t, err, tt.err)
				}),
			)

			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.tokenFunc != nil {
				req.AddCookie(&http.Cookie{
					Name:  cookieName,
					Value: tt.tokenFunc(t, h, &http.Request{}),
				})
			}
			resp := httptest.NewRecorder()
			s.ServeHTTP(resp, req)
			assert.Equal(t, tt.statusCode, resp.Code)
		})
	}
}
