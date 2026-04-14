package authn

import (
	"net/url"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticator(t *testing.T) {
	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)
	t.Cleanup(func() { _ = oidcServer.Shutdown() })

	config := configuration.Configuration{
		Authn: configuration.AuthnConfiguration{
			StateTTL: 5 * time.Minute,
			Provider: provider.Configuration{
				Type: "oidc",
				OIDC: provider.OIDCConfiguration{
					ClientID:     oidcServer.Config().ClientID,
					ClientSecret: oidcServer.Config().ClientSecret,
					RedirectURL:  "https://auth.example.com",
					IssuerURL:    oidcServer.Issuer(),
				},
			},
		},
	}

	ctx := t.Context()
	fa, err := New(ctx, config)
	require.NoError(t, err)

	// initiate a login request: generate the login URL
	u, err := fa.InitiateLogin(ctx, "www.example.com")
	require.NoError(t, err)
	assert.NotZero(t, u)

	// login URL should contain a state parameter
	parsedURL, err := url.Parse(u)
	require.NoError(t, err)
	state := parsedURL.Query().Get("state")
	assert.NotZero(t, state)

	// mockoidc: queue the user for login
	oidcUser := mockoidc.MockUser{
		Subject:       "foo",
		Email:         "foo@example.com",
		EmailVerified: true,
	}
	sess, err := oidcServer.SessionStore.NewSession("oidc profile email", "", &oidcUser, "", "")
	require.NoError(t, err)
	code := sess.SessionID

	// user has logged in and oidc has sent the confirmation request
	userInfo, u, err := fa.ConfirmLogin(ctx, state, code)
	require.NoError(t, err)
	assert.Equal(t, oidcUser.Email, userInfo.Email)
	assert.Equal(t, "www.example.com", u)
}
