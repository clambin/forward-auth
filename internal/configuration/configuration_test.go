package configuration

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clambin/forward-auth/internal/authz"
	"github.com/goccy/go-yaml"
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
		{"text", LoggerConfiguration{Level: "INFO", Format: "text"}, `level=INFO msg=test`},
		{"json", LoggerConfiguration{Level: "INFO", Format: "json"}, `"level":"INFO","msg":"test"`},
		{"invalid level", LoggerConfiguration{Level: "invalid", Format: "text"}, "invalid log level: invalid. using INFO"},
		{"invalid format", LoggerConfiguration{Level: "INFO", Format: "invalid"}, "invalid log format: invalid. using text"},
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
	cfg := DefaultConfiguration
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
}

func TestConfiguration_IsValid(t *testing.T) {
	// blank configuration is invalid
	require.Error(t, Configuration{}.IsValid())

	// default configuration is invalid
	cfg := DefaultConfiguration
	require.Error(t, cfg.IsValid())

	// fill in all mandatory fields
	cfg.Server.Key = strings.Repeat("a", 32)
	cfg.Server.Domain = "example.com"
	cfg.Authn.Provider.RedirectURL = "https://example.com"
	cfg.Authn.Provider.OIDC.IssuerURL = "https://example.com"
	cfg.Authn.Provider.OIDC.ClientID = "my-client-id"
	cfg.Authn.Provider.OIDC.ClientSecret = "my-client-secret"
	require.NoError(t, cfg.IsValid())

	// change provider type to github and validate mandatory fields
	cfg.Authn.Provider.Type = "github"
	require.Error(t, cfg.IsValid())
	cfg.Authn.Provider.GitHub.ClientID = "my-client-id"
	cfg.Authn.Provider.GitHub.ClientSecret = "my-client-secret"
	require.NoError(t, cfg.IsValid())

	// change storage type to redis and validate mandatory fields
	cfg.Storage.Type = "redis"
	require.Error(t, cfg.IsValid())
	cfg.Storage.Redis.Addr = "127.0.0.1:6379"
	require.NoError(t, cfg.IsValid())

	// key that is too short is rejected
	cfg.Server.Key = "too-short"
	err := cfg.IsValid()
	require.Error(t, err)
	assert.Equal(t, "server: key: must be at least 32 characters long", err.Error())
}
