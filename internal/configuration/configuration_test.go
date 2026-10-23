package configuration

import (
	"bytes"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/clambin/go-common/validate"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/goccy/go-yaml"
	"github.com/sethvargo/go-envconfig/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update testdata")

func TestLoggerConfiguration_Logger(t *testing.T) {
	tests := []struct {
		name string
		cfg  LoggerConfiguration
		want string
	}{
		{"text", LoggerConfiguration{Level: slog.LevelInfo, Format: "text"}, `level=INFO msg=test`},
		{"json", LoggerConfiguration{Level: slog.LevelInfo, Format: "json"}, `"level":"INFO","msg":"test"`},
		{"invalid format", LoggerConfiguration{Level: slog.LevelInfo, Format: "invalid"}, "invalid log format: invalid. using text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buff bytes.Buffer
			l := tt.cfg.Logger(&buff)
			l.Info("test")
			assert.Contains(t, buff.String(), tt.want)
		})
	}
}

func TestConfiguration_Unmarshal(t *testing.T) {
	cfg := Default()
	cfg.Server.Key = "my-token-signing-key"
	cfg.Authz = AuthzConfiguration{
		Rules: []authz.Rule{
			{Domain: "*.example.com", Groups: []string{"users"}},
		},
		Groups: []authz.Group{
			{Name: "users", Users: []string{"foo@example.com"}},
		},
	}
	cfg.Authn.Provider.RedirectURL = "https://auth.example.com/api/auth/login"
	cfg.Authn.Provider.OIDC.ClientID = "1234"
	cfg.Authn.Provider.OIDC.ClientSecret = "5678"
	cfg.Authn.Provider.OIDC.IssuerURL = "https://auth.example.com/oidc"
	cfg.Storage = StorageConfiguration{
		Type: "redis",
		Redis: StorageRedisConfiguration{
			Addr:     "localhost:6379",
			Username: "my-user",
			Password: "my-password",
			DB:       10,
		},
	}

	body, err := yaml.Marshal(cfg)
	require.NoError(t, err)

	gp := filepath.Join("testdata", strings.ToLower(t.Name())+".golden.yaml")
	if *update {
		require.NoError(t, os.WriteFile(gp, body, 0644))
	}
	golden, err := os.ReadFile(gp)
	require.NoError(t, err)

	assert.Equal(t, string(golden), string(body))

	var cfg2 Configuration
	require.NoError(t, yaml.Unmarshal(golden, &cfg2))
	assert.Equal(t, cfg, cfg2)
}

func TestConfiguration_IsValid(t *testing.T) {
	// blank configuration is invalid
	require.Error(t, validate.Validate(Configuration{}))

	// default configuration is invalid
	cfg := Default()
	require.Error(t, validate.Validate(cfg))

	// fill in all mandatory fields
	cfg.Server.Key = strings.Repeat("a", 32)
	cfg.Server.Domain = "example.com"
	cfg.Authn.Provider.RedirectURL = "https://example.com"
	cfg.Authn.Provider.OIDC.IssuerURL = "https://example.com"
	cfg.Authn.Provider.OIDC.ClientID = "my-client-id"
	cfg.Authn.Provider.OIDC.ClientSecret = "my-client-secret"
	require.NoError(t, validate.Validate(cfg))

	// change provider type to github and validate mandatory fields
	cfg.Authn.Provider.Type = "github"
	require.Error(t, validate.Validate(cfg))
	cfg.Authn.Provider.GitHub.ClientID = "my-client-id"
	cfg.Authn.Provider.GitHub.ClientSecret = "my-client-secret"
	require.NoError(t, validate.Validate(cfg))

	// change storage type to redis and validate mandatory fields
	cfg.Storage.Type = "redis"
	require.Error(t, validate.Validate(cfg))
	cfg.Storage.Redis.Addr = "127.0.0.1:6379"
	require.NoError(t, validate.Validate(cfg))

	// key that is too short is rejected
	cfg.Server.Key = "too-short"
	err := validate.Validate(cfg)
	require.Error(t, err)
	assert.Equal(t, "server: key: must be at least 32 characters long", err.Error())
}

func TestProviderConfiguration_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ProviderConfiguration
		wantErr require.ErrorAssertionFunc
	}{
		{"invalid type", ProviderConfiguration{Type: "invalid"}, require.Error},
		{"valid oidc", ProviderConfiguration{Type: "oidc", RedirectURL: "https://example.com", OIDC: OIDCProviderConfiguration{"https://example.xom", "ClientID", "ClientSecret", []string{}}}, require.NoError},
		{"valid github", ProviderConfiguration{Type: "github", RedirectURL: "https://example.com", GitHub: GitHubProviderConfiguration{"ClientID", "ClientSecret", []string{}}}, require.NoError},
		{"blank", ProviderConfiguration{}, require.Error},
		{"invalid redirect url", ProviderConfiguration{Type: "oidc", RedirectURL: "", OIDC: OIDCProviderConfiguration{"https://example.xom", "ClientID", "ClientSecret", []string{}}}, require.Error},
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
		cfg     OIDCProviderConfiguration
		wantErr require.ErrorAssertionFunc
	}{
		{"blank", OIDCProviderConfiguration{}, require.Error},
		{"no issuer", OIDCProviderConfiguration{"", "ClientID", "ClientSecret", []string{}}, require.Error},
		{"no client id", OIDCProviderConfiguration{"https://example.xom", "", "ClientSecret", []string{}}, require.Error},
		{"no client secret", OIDCProviderConfiguration{"https://example.xom", "ClientID", "", []string{}}, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.isValid()
			tt.wantErr(t, err)
		})
	}
}

func TestGitHubConfiguration_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		cfg     GitHubProviderConfiguration
		wantErr require.ErrorAssertionFunc
	}{
		{"blank", GitHubProviderConfiguration{}, require.Error},
		{"no client id", GitHubProviderConfiguration{"", "ClientSecret", []string{}}, require.Error},
		{"no client secret", GitHubProviderConfiguration{"ClientID", "", []string{}}, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.isValid()
			tt.wantErr(t, err)
		})
	}
}

// TestEnvVars tests that configuration supports the expected environment variables
func TestEnvVars(t *testing.T) {
	want := []string{
		"AUTHN_PROVIDER_GITHUB_CLIENT_ID",
		"AUTHN_PROVIDER_GITHUB_CLIENT_SECRET",
		"AUTHN_PROVIDER_OIDC_CLIENT_ID",
		"AUTHN_PROVIDER_OIDC_CLIENT_SECRET",
		"SERVER_KEY",
		"STORAGE_REDIS_PASSWORD",
		"STORAGE_REDIS_USERNAME",
	}
	assert.Equal(t, want, envVars(Configuration{}))
}

func TestConfiguration_EnvVars(t *testing.T) {
	cfg := Default()
	err := envconfig.ProcessWith(t.Context(), &envconfig.Config{
		Target:   &cfg,
		Lookuper: envconfig.MapLookuper(map[string]string{"STORAGE_REDIS_PASSWORD": "password"}),
	})
	require.NoError(t, err)
	assert.Equal(t, "password", cfg.Storage.Redis.Password)
}
