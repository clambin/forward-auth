package provider

import (
	"testing"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOidcProvider_GetUserInfo(t *testing.T) {
	// OIDC
	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)
	t.Cleanup(func() { _ = oidcServer.Shutdown() })
	cfg := configuration.OIDCProviderConfiguration{
		ClientID:     oidcServer.Config().ClientID,
		ClientSecret: oidcServer.Config().ClientSecret,
		IssuerURL:    oidcServer.Issuer(),
	}

	p, err := newOIDCProvider(t.Context(), "", cfg)
	require.NoError(t, err)

	oidcCode := func(email string) string {
		u := mockoidc.MockUser{
			Email:         email,
			EmailVerified: true,
		}
		session, err := oidcServer.SessionStore.NewSession("openid profile email", "", &u, "", "")
		require.NoError(t, err)
		return session.SessionID
	}

	code := oidcCode("test@example.com")
	tok, err := p.Exchange(t.Context(), code)
	require.NoError(t, err)
	info, err := p.GetUserInfo(t.Context(), tok)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", info.Email)

	tok2 := tok.WithExtra(map[string]any{"id_token": ""})
	info, err = p.GetUserInfo(t.Context(), tok2)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", info.Email)

}
