package provider

import (
	"net/url"
	"testing"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCProvider(t *testing.T) {
	s, err := mockoidc.Run()
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Shutdown() })

	ctx := t.Context()
	config := Configuration{
		Type: "oidc",
		OIDC: OIDCConfiguration{
			ClientID:     s.Config().ClientID,
			ClientSecret: s.Config().ClientSecret,
			RedirectURL:  "https://auth.example.com",
			IssuerURL:    s.Issuer(),
		},
	}

	a, err := New(ctx, config)
	require.NoError(t, err)

	u := mockoidc.MockUser{
		Subject:       "foo",
		Email:         "foo@example.com",
		EmailVerified: true,
	}
	session, err := s.SessionStore.NewSession("openid profile email", "", &u, "", "")
	require.NoError(t, err)
	code := session.SessionID

	parsedURL, err := url.Parse(a.AuthCodeURL("https://example.com"))
	require.NoError(t, err)
	state := parsedURL.Query().Get("state")
	require.NotZero(t, state)

	token, err := a.Exchange(ctx, code)
	require.NoError(t, err)

	userInfo, err := a.GetUserInfo(ctx, token)
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", userInfo.Email)
}
