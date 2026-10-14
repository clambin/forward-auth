package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
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
			h := WithForwardAuthToken(cookieName, validKey, LaxTokenMode)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := TokenFromRequest(r)
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

func TestWithReqIDLogger(t *testing.T) {
	tests := []struct {
		name string
		mw   func(*slog.Logger) func(http.Handler) http.Handler
		re   *regexp.Regexp
	}{
		{"log", WithLogger, regexp.MustCompile(`^level=INFO msg="hello world"\n$`)},
		{"reqID", WithReqIDLogger, regexp.MustCompile(`^level=INFO msg="hello world" reqID=`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					if a.Key == slog.TimeKey {
						return slog.Attr{}
					}
					return a
				},
			}))

			h := tt.mw(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Logger(r).Info("hello world")
			}))

			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, http.StatusOK, resp.Code)

			output := buf.String()
			assert.True(t, tt.re.MatchString(output))
		})
	}
}
