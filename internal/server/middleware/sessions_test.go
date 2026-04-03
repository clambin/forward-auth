package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/stretchr/testify/require"
)

func TestSessionMiddleware(t *testing.T) {
	tests := []struct {
		name   string
		auth   Authenticator
		cookie *http.Cookie
		strict bool
		want   int
	}{
		{"valid", fakeAuthenticator{session: &authn.Session{}}, &http.Cookie{Name: "test-cookie"}, true, http.StatusOK},
		{"strict - cookie missing", fakeAuthenticator{session: &authn.Session{}}, nil, true, http.StatusUnauthorized},
		{"strict - invalid cookie", fakeAuthenticator{err: errors.New("invalid")}, &http.Cookie{Name: "test-cookie"}, true, http.StatusUnauthorized},
		{"lax - cookie missing", fakeAuthenticator{session: &authn.Session{}}, nil, false, http.StatusOK},
		{"lax - invalid cookie", fakeAuthenticator{err: errors.New("invalid")}, &http.Cookie{Name: "test-cookie"}, false, http.StatusOK},
		{"lax - valid cookie", fakeAuthenticator{session: &authn.Session{}}, &http.Cookie{Name: "test-cookie"}, false, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := WithSessionValidation("test-cookie", tt.auth, tt.strict)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, ok := SessionFromCtx(r.Context())
				if !ok && tt.strict {
					http.Error(w, "no valid session cookie found", http.StatusUnauthorized)
					return
				}
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			require.Equal(t, tt.want, resp.Code)
		})
	}
}

var _ Authenticator = (*fakeAuthenticator)(nil)

type fakeAuthenticator struct {
	session *authn.Session
	err     error
}

func (f fakeAuthenticator) Validate(_ context.Context, _ string) (*authn.Session, error) {
	return f.session, f.err
}
