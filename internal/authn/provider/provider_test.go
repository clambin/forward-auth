package provider

import (
	"net/url"
	"testing"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider(t *testing.T) {
	// OIDC
	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)
	t.Cleanup(func() { _ = oidcServer.Shutdown() })
	oidcCfg := configuration.ProviderConfiguration{
		Type: "oidc",
		OIDC: configuration.OIDCProviderConfiguration{
			ClientID:     oidcServer.Config().ClientID,
			ClientSecret: oidcServer.Config().ClientSecret,
			IssuerURL:    oidcServer.Issuer(),
		},
	}
	invalidOidcCfg := oidcCfg
	invalidOidcCfg.OIDC.IssuerURL = ""

	oidcCode := func(email string) string {
		u := mockoidc.MockUser{
			Email:         email,
			EmailVerified: true,
		}
		session, err := oidcServer.SessionStore.NewSession("openid profile email", "", &u, "", "")
		require.NoError(t, err)
		return session.SessionID
	}

	tests := []struct {
		name    string
		cfg     configuration.ProviderConfiguration
		code    func(email string) string
		wantErr require.ErrorAssertionFunc
	}{
		{"oidc", oidcCfg, oidcCode, require.NoError},
		{"oidc bad config", invalidOidcCfg, oidcCode, require.Error},
		{"invalid type", configuration.ProviderConfiguration{Type: "invalid"}, nil, require.Error},
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
