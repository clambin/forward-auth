package authn

import (
	"context"
	"fmt"
)

type Configuration struct {
	Type string            `yaml:"type"`
	OIDC OIDCConfiguration `yaml:"oidc"`
}

type OIDCConfiguration struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
	IssuerURL    string `yaml:"issuer_url"`
}

type UserInfo struct {
	Subject string
	Profile string
	Email   string
}

type Authenticator interface {
	AuthURL(string) string
	GetUserInfo(context.Context, string) (*UserInfo, error)
}

var _ Authenticator = (*oidcAuthenticator)(nil)

func New(ctx context.Context, configuration Configuration) (Authenticator, error) {
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
		return nil, fmt.Errorf("unsupported authn type: %s", configuration.Type)
	}
}
