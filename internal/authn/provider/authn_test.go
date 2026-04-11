package provider

import (
	"net/url"
	"testing"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCAuthenticator(t *testing.T) {
	s, err := mockoidc.Run()
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Shutdown() })

	ctx := t.Context()
	config := Configuration{
		Type: "oidc",
		OIDC: OIDCConfiguration{
			ClientID:      s.Config().ClientID,
			ClientSecret:  s.Config().ClientSecret,
			RedirectURL:   "https://auth.example.com",
			IssuerURL:     s.Issuer(),
			SelectAccount: true,
		},
	}

	a, err := New(ctx, config)
	require.NoError(t, err)

	_, err = a.GetUserInfo(ctx, "invalid-code")
	require.Error(t, err)

	u := mockoidc.MockUser{
		Subject:       "foo",
		Email:         "foo@example.com",
		EmailVerified: true,
	}
	session, err := s.SessionStore.NewSession("oidc profile email", "", &u, "", "")
	require.NoError(t, err)
	code := session.SessionID

	parsedURL, err := url.Parse(a.AuthCodeURL("https://example.com"))
	require.NoError(t, err)
	state := parsedURL.Query().Get("state")
	require.NotZero(t, state)

	userInfo, err := a.GetUserInfo(ctx, code)
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", userInfo.Email)
}

func TestOIDCAuthenticator_SelectAccount(t *testing.T) {
	s, err := mockoidc.Run()
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Shutdown() })

	// select_account
	config := Configuration{
		Type: "oidc",
		OIDC: OIDCConfiguration{
			ClientID:      s.Config().ClientID,
			ClientSecret:  s.Config().ClientSecret,
			RedirectURL:   "https://auth.example.com",
			IssuerURL:     s.Issuer(),
			SelectAccount: true,
		},
	}

	a, err := New(t.Context(), config)
	require.NoError(t, err)
	u, err := url.Parse(a.AuthCodeURL("https://www.example.com"))
	require.NoError(t, err)
	assert.Equal(t, "select_account", u.Query().Get("prompt"))

	// no select_account
	config.OIDC.SelectAccount = false

	a, err = New(t.Context(), config)
	require.NoError(t, err)
	u, err = url.Parse(a.AuthCodeURL("https://www.example.com"))
	require.NoError(t, err)
	assert.Zero(t, u.Query().Get("prompt"))
}
