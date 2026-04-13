package provider

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oidcAuthenticator handles the OIDC authentication flow.
type oidcAuthenticator struct {
	config        oauth2.Config
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	selectAccount bool
}

// newOIDCAuthenticator creates a new oidcAuthenticator.
func newOIDCAuthenticator(ctx context.Context, configuration OIDCConfiguration) (*oidcAuthenticator, error) {
	var err error
	a := oidcAuthenticator{selectAccount: configuration.SelectAccount}
	if a.provider, err = oidc.NewProvider(ctx, configuration.IssuerURL); err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}
	a.verifier = a.provider.Verifier(&oidc.Config{ClientID: configuration.ClientID})
	a.config = oauth2.Config{
		ClientID:     configuration.ClientID,
		ClientSecret: configuration.ClientSecret,
		Endpoint:     a.provider.Endpoint(),
		RedirectURL:  configuration.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return &a, nil
}

// AuthCodeURL returns the login URL to redirect the user to.
func (o *oidcAuthenticator) AuthCodeURL(state string) string {
	var opts []oauth2.AuthCodeOption
	if o.selectAccount {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account"))
	}
	return o.config.AuthCodeURL(state, opts...)
}

// GetUserInfo completes the OIDC authentication flow and, if successful, returns the user info.
func (o *oidcAuthenticator) GetUserInfo(ctx context.Context, code string) (Identity, error) {
	// exchange the code for an access token
	token, err := o.config.Exchange(ctx, code)
	if err != nil {
		return Identity{}, fmt.Errorf("exchange code: %w", err)
	}

	// verify the ID token
	if rawIDToken, ok := token.Extra("id_token").(string); ok {
		return getIdentityFromToken(ctx, o.verifier, rawIDToken)
	}

	userInfo, err := o.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return Identity{}, fmt.Errorf("get user info: %w", err)
	}

	var id Identity
	if err = userInfo.Claims(&id); err != nil {
		return Identity{}, fmt.Errorf("parse claims: %w", err)
	}

	slog.Info("User info parsed", "user", id)

	return id, nil
}

func getIdentityFromToken(ctx context.Context, v *oidc.IDTokenVerifier, rawIDToken string) (Identity, error) {
	slog.Info("raw ID Token found")

	idToken, err := v.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify id token: %w", err)
	}

	slog.Info("ID Token verified")

	var id Identity

	if err = idToken.Claims(&id); err != nil {
		return Identity{}, fmt.Errorf("parse claims: %w", err)
	}

	slog.Info("ID Token claims parsed", "claims", id)

	return id, nil
}
