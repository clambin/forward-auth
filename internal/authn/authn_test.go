package authn

import (
	"net/url"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/cache"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessions(t *testing.T) {
	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)

	config := configuration.AuthnConfiguration{
		SessionTTL: 5 * time.Minute,
		StateTTL:   5 * time.Minute,
		Provider: provider.Configuration{
			Type: "oidc",
			OIDC: provider.OIDCConfiguration{
				ClientID:     oidcServer.Config().ClientID,
				ClientSecret: oidcServer.Config().ClientSecret,
				RedirectURL:  "https://auth.example.com",
				IssuerURL:    oidcServer.Issuer(),
			},
		},
	}

	ctx := t.Context()
	fa, err := New(ctx, config)
	require.NoError(t, err)

	// no session exists: request should be denied
	var sessionID string
	session, err := fa.Validate(ctx, sessionID)
	require.ErrorIs(t, err, cache.ErrNotFound)
	assert.Zero(t, session)

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
	session, sessionID, u, ttl, err := fa.ConfirmLogin(ctx, state, code)
	require.NoError(t, err)
	assert.Equal(t, oidcUser.Email, session.UserInfo.Email)
	assert.NotZero(t, sessionID)
	assert.Equal(t, "www.example.com", u)
	assert.Equal(t, config.SessionTTL, ttl)

	// session should now exist
	session, err = fa.Validate(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, oidcUser.Email, session.UserInfo.Email)
}
