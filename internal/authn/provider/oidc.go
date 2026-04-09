package provider

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oidcAuthenticator handles the OIDC authentication flow.
type oidcAuthenticator struct {
	config   oauth2.Config
	provider *oidc.Provider
}

func newOIDCAuthenticator(ctx context.Context, configuration OIDCConfiguration) (*oidcAuthenticator, error) {
	var a oidcAuthenticator
	var err error
	if a.provider, err = oidc.NewProvider(ctx, configuration.IssuerURL); err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}
	a.config = oauth2.Config{
		ClientID:     configuration.ClientID,
		ClientSecret: configuration.ClientSecret,
		Endpoint:     a.provider.Endpoint(),
		RedirectURL:  configuration.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return &a, nil
}

// AuthURL returns the login URL to redirect the user to.
func (o *oidcAuthenticator) AuthURL(state string) string {
	// TODO: add option to always prompt the used to select an account:
	//oauth2.SetAuthURLParam("prompt", "select_account"),
	return o.config.AuthCodeURL(state)
}

// GetUserInfo completes the OIDC authentication flow and, if successful, returns the user info.
func (o *oidcAuthenticator) GetUserInfo(ctx context.Context, code string) (UserInfo, error) {
	token, err := o.config.Exchange(ctx, code)
	if err != nil {
		return UserInfo{}, fmt.Errorf("exchange code: %w", err)
	}

	userInfo, err := o.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return UserInfo{}, fmt.Errorf("get user info: %w", err)
	}

	var info UserInfo
	if err = userInfo.Claims(&info); err != nil {
		return UserInfo{}, fmt.Errorf("parse claims: %w", err)
	}
	return info, nil
}
