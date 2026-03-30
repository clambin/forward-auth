package authn

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

	loginURL := a.AuthURL("https://example.com")
	require.NotZero(t, loginURL)

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

	loginURL = a.AuthURL("https://example.com")
	parsedURL, err := url.Parse(loginURL)
	require.NoError(t, err)
	state := parsedURL.Query().Get("state")
	require.NotZero(t, state)

	userInfo, err := a.GetUserInfo(ctx, code)
	require.NoError(t, err)
	assert.Equal(t, "foo@example.com", userInfo.Email)
}
