package provider

import (
	"context"
	"fmt"
)

type Configuration struct {
	Type string            `yaml:"type"`
	OIDC OIDCConfiguration `yaml:"oidc"`
}

type OIDCConfiguration struct {
	ClientID      string `yaml:"client_id"`
	ClientSecret  string `yaml:"client_secret"`
	RedirectURL   string `yaml:"redirect_url"`
	IssuerURL     string `yaml:"issuer_url"`
	SelectAccount bool   `yaml:"select_account"`
}

// note: this works with Google's OIDC provider. May not work 100% with other providers.

type Identity struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	EmailVerified bool   `json:"email_verified"`
}

// Provider is an interface for an authentication provider.
type Provider interface {
	AuthCodeURL(string) string
	GetUserInfo(context.Context, string) (Identity, error)
}

var _ Provider = (*oidcAuthenticator)(nil)

// New creates a new authentication provider for the provided configuration.
func New(ctx context.Context, configuration Configuration) (Provider, error) {
	switch configuration.Type {
	case "google":
		configuration.Type = "oidc"
		configuration.OIDC.IssuerURL = "https://accounts.google.com"
		return New(ctx, configuration)
	case "oidc":
		a, err := newOIDCAuthenticator(ctx, configuration.OIDC)
		if err != nil {
			return nil, fmt.Errorf("oidc authenticator: %w", err)
		}
		return a, nil
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", configuration.Type)
	}
}
