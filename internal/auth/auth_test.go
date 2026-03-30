package auth

import (
	"net/url"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/auth/authn"
	"github.com/clambin/forward-auth/internal/auth/authz"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForwardAuth(t *testing.T) {
	s, err := mockoidc.Run()
	require.NoError(t, err)

	config := Configuration{
		SessionTTL: 5 * time.Minute,
		StateTTL:   5 * time.Minute,
		Authn: authn.Configuration{
			Type: "oidc",
			OIDC: authn.OIDCConfiguration{
				ClientID:     s.Config().ClientID,
				ClientSecret: s.Config().ClientSecret,
				RedirectURL:  "https://auth.example.com",
				IssuerURL:    s.Issuer(),
			},
		},
		Authz: authz.Configuration{
			Rules: []authz.Rule{
				{
					Domain: "*.example.com",
					Users:  []string{"foo@example.com"},
				},
			},
		},
	}

	ctx := t.Context()
	fa, err := New(ctx, config)
	require.NoError(t, err)

	// no session exists: request should be denied
	var sessionID string
	user, err := fa.ValidateSession(ctx, sessionID, &url.URL{Host: "www.example.com"})
	require.ErrorIs(t, err, ErrNoSession)
	assert.Zero(t, user)

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
	session, err := s.SessionStore.NewSession("oidc profile email", "", &oidcUser, "", "")
	require.NoError(t, err)
	code := session.SessionID

	// user has logged in and oidc has sent the confirmation request
	user, sessionID, u, ttl, err := fa.ConfirmLogin(ctx, state, code)
	require.NoError(t, err)
	assert.Equal(t, oidcUser.Email, user.Email)
	assert.NotZero(t, sessionID)
	assert.Equal(t, "www.example.com", u)
	assert.Equal(t, config.SessionTTL, ttl)

	// session should now exist
	user, err = fa.ValidateSession(ctx, sessionID, &url.URL{Host: "www.example.com"})
	require.NoError(t, err)
	assert.Equal(t, oidcUser.Email, user.Email)
}
