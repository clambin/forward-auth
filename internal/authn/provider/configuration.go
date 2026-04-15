package provider

type Configuration struct {
	Type        string              `yaml:"type"`
	RedirectURL string              `yaml:"redirect_url"`
	OIDC        OIDCConfiguration   `yaml:"oidc"`
	GitHub      GitHubConfiguration `yaml:"github"`
}

type OIDCConfiguration struct {
	IssuerURL    string   `yaml:"issuer_url"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
}

type GitHubConfiguration struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
}
