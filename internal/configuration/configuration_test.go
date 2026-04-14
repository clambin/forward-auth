package configuration

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
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
	cfg := Configuration{
		Server: ServerConfiguration{
			Addr:       ":8080",
			Domain:     ".example.com",
			CookieName: "session",
		},
		Logger: LoggerConfiguration{
			Level:  "info",
			Format: "text",
		},
		Prometheus: PrometheusConfiguration{
			Addr: ":9100",
			Path: "/metrics",
		},
		Authz: AuthzConfiguration{
			Rules: []authz.Rule{
				{Domain: "*.example.com", Groups: []string{"users"}},
			},
			Groups: []authz.Group{
				{Name: "users", Users: []string{"foo@example.com"}},
			},
		},
		Authn: AuthnConfiguration{
			Provider: provider.Configuration{
				Type:         "oidc",
				ClientID:     "1234",
				ClientSecret: "5678",
				RedirectURL:  "https://auth.example.com/api/auth/login",
				IssuerURL:    "https://auth.example.com/oidc",
			},
			StateTTL:      5 * time.Minute,
			SelectAccount: true,
		},
		Storage: StorageConfiguration{
			Type: "redis",
			Redis: StorageRedisConfiguration{
				Addr:     "localhost:6379",
				Username: "my-user",
				Password: "my-password",
				DB:       10,
			},
		},
		Session: SessionConfiguration{
			SessionTTL: 24 * time.Hour,
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
