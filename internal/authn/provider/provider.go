package provider

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

type Configuration struct {
	Type          string            `yaml:"type"`
	OIDC          OIDCConfiguration `yaml:"oidc"`
	SelectAccount bool              `yaml:"select_account"`
}

type OIDCConfiguration struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
	IssuerURL    string `yaml:"issuer_url"`
}

type Identity struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}

// Provider is an interface for an authentication provider.
type Provider interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (Identity, error)
}

// New creates a new authentication provider for the provided configuration.
func New(ctx context.Context, configuration Configuration) (Provider, error) {
	switch configuration.Type {
	case "google":
		configuration.Type = "oidc"
		configuration.OIDC.IssuerURL = "https://accounts.google.com"
		return New(ctx, configuration)
	case "oidc":
		a, err := newOIDCProvider(ctx, configuration.OIDC)
		if err != nil {
			return nil, fmt.Errorf("oidc authenticator: %w", err)
		}
		return a, nil
	case "github":
		return newGitHubProvider(configuration.OIDC), nil
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", configuration.Type)
	}
}
