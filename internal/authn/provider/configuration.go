package provider

import (
	"errors"

	"github.com/clambin/forward-auth/internal/configuration/validate"
)

type Configuration struct {
	Type        string              `yaml:"type"`
	RedirectURL string              `yaml:"redirect_url"`
	OIDC        OIDCConfiguration   `yaml:"oidc"`
	GitHub      GitHubConfiguration `yaml:"github"`
}

func (c Configuration) IsValid() error {
	errs := errors.Join(
		validate.PrefixError("type", validate.IsEnum(c.Type, "oidc", "github")),
		validate.PrefixError("redirect_url", validate.IsNotZero(c.RedirectURL)),
	)
	switch c.Type {
	case "oidc":
		errs = errors.Join(errs, validate.PrefixError("oidc", c.OIDC.IsValid()))
	case "github":
		errs = errors.Join(errs, validate.PrefixError("github", c.GitHub.IsValid()))
	}
	return errs
}

type OIDCConfiguration struct {
	IssuerURL    string   `yaml:"issuer_url"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
}

func (c OIDCConfiguration) IsValid() error {
	return errors.Join(
		validate.PrefixError("issuer_url", validate.IsNotZero(c.IssuerURL)),
		validate.PrefixError("client_id", validate.IsNotZero(c.ClientID)),
		validate.PrefixError("client_secret", validate.IsNotZero(c.ClientSecret)),
	)
}

type GitHubConfiguration struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
}

func (c GitHubConfiguration) IsValid() error {
	return errors.Join(
		validate.PrefixError("client_id", validate.IsNotZero(c.ClientID)),
		validate.PrefixError("client_secret", validate.IsNotZero(c.ClientSecret)),
	)
}
