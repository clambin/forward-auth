package provider

import (
	"net/url"
	"testing"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider(t *testing.T) {
	// OIDC
	s, err := mockoidc.Run()
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Shutdown() })
	oidcCfg := Configuration{
		Type: "oidc",
		OIDC: OIDCConfiguration{
			ClientID:     s.Config().ClientID,
			ClientSecret: s.Config().ClientSecret,
			IssuerURL:    s.Issuer(),
		},
	}
	oidcCode := func(email string) string {
		u := mockoidc.MockUser{
			Email:         email,
			EmailVerified: true,
		}
		session, err := s.SessionStore.NewSession("openid profile email", "", &u, "", "")
		require.NoError(t, err)
		return session.SessionID
	}

	tests := []struct {
		name    string
		cfg     Configuration
		code    func(email string) string
		wantErr require.ErrorAssertionFunc
	}{
		{"oidc", oidcCfg, oidcCode, require.NoError},
		{"invalid", Configuration{Type: "invalid"}, nil, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := New(t.Context(), tt.cfg)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			parsedURL, err := url.Parse(provider.AuthCodeURL("https://example.com"))
			require.NoError(t, err)
			state := parsedURL.Query().Get("state")
			require.NotZero(t, state)

			token, err := provider.Exchange(t.Context(), tt.code("foo@example.com"))
			require.NoError(t, err)

			userInfo, err := provider.GetUserInfo(t.Context(), token)
			require.NoError(t, err)
			assert.Equal(t, "foo@example.com", userInfo.Email)

		})
	}
}
