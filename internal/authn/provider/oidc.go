package provider

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var _ Provider = (*oidcProvider)(nil)

// oidcProvider authenticates the user using OIDC.
type oidcProvider struct {
	oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// newOIDCProvider creates a new oidcProvider.
func newOIDCProvider(ctx context.Context, configuration Configuration) (*oidcProvider, error) {
	var err error
	var a oidcProvider
	if a.provider, err = oidc.NewProvider(ctx, configuration.IssuerURL); err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}
	a.verifier = a.provider.Verifier(&oidc.Config{ClientID: configuration.ClientID})
	a.Config = oauth2.Config{
		ClientID:     configuration.ClientID,
		ClientSecret: configuration.ClientSecret,
		Endpoint:     a.provider.Endpoint(),
		RedirectURL:  configuration.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return &a, nil
}

// GetUserInfo completes the OIDC authentication flow and, if successful, returns the user info.
func (o *oidcProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (Identity, error) {
	var id Identity
	var err error

	// verify the ID token. If we get an id_token, use that to retrieve the user's Identity.
	if rawIDToken, ok := token.Extra("id_token").(string); ok {
		if id, err = getIdentityFromToken(ctx, o.verifier, rawIDToken); err == nil {
			return id, nil
		}

		// TODO: remove this log line once we have a better way to handle this.
		slog.Warn("failed to get identity from id token. Using provider's user info endpoint instead", "err", err)
	}

	// Otherwise, use the access token to retrieve the user's Identity from the provider's user info endpoint.
	userInfo, err := o.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return Identity{}, fmt.Errorf("get user info: %w", err)
	}

	if err = userInfo.Claims(&id); err != nil {
		return Identity{}, fmt.Errorf("parse claims: %w", err)
	}

	return id, nil
}

func getIdentityFromToken(ctx context.Context, v *oidc.IDTokenVerifier, rawIDToken string) (Identity, error) {
	idToken, err := v.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify id token: %w", err)
	}

	var id Identity
	if err = idToken.Claims(&id); err != nil {
		return Identity{}, fmt.Errorf("parse claims: %w", err)
	}

	return id, nil
}
