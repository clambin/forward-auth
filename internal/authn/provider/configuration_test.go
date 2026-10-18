package provider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfiguration_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Configuration
		wantErr require.ErrorAssertionFunc
	}{
		{"blank", Configuration{}, require.Error},
		{"invalid type", Configuration{Type: "invalid"}, require.Error},
		{"valid oidc", Configuration{Type: "oidc", RedirectURL: "https://example.com", OIDC: OIDCConfiguration{"https://example.xom", "ClientID", "ClientSecret", []string{}}}, require.NoError},
		{"valid github", Configuration{Type: "github", RedirectURL: "https://example.com", GitHub: GitHubConfiguration{"ClientID", "ClientSecret", []string{}}}, require.NoError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.IsValid()
			tt.wantErr(t, err)
		})
	}
}

func TestOIDCConfiguration_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		cfg     OIDCConfiguration
		wantErr require.ErrorAssertionFunc
	}{
		{"blank", OIDCConfiguration{}, require.Error},
		{"no issuer", OIDCConfiguration{"", "ClientID", "ClientSecret", []string{}}, require.Error},
		{"no client id", OIDCConfiguration{"https://example.xom", "", "ClientSecret", []string{}}, require.Error},
		{"no client secret", OIDCConfiguration{"https://example.xom", "ClientID", "", []string{}}, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.IsValid()
			tt.wantErr(t, err)
		})
	}
}

func TestGitHubConfiguration_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		cfg     GitHubConfiguration
		wantErr require.ErrorAssertionFunc
	}{
		{"blank", GitHubConfiguration{}, require.Error},
		{"no client id", GitHubConfiguration{"", "ClientSecret", []string{}}, require.Error},
		{"no client secret", GitHubConfiguration{"ClientID", "", []string{}}, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.IsValid()
			tt.wantErr(t, err)
		})
	}
}
