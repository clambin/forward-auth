package configuration

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"codeberg.org/clambin/go-common/httputils"
	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/configuration/validate"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var DefaultConfiguration = Configuration{
	Server: ServerConfiguration{
		CookieName: "forward-auth-session",
		Key:        "change-me!",
		HealthPath: "/healthz",
		AddrInt:    ":8080",
		AddrExt:    ":8081",
	},
	Logger: LoggerConfiguration{
		Level:  "info",
		Format: "text",
	},
	Prometheus: PrometheusConfiguration{
		Addr: ":9120",
		Path: "/metrics",
	},
	Authn: AuthnConfiguration{
		StateTTL: 10 * time.Minute,
		Provider: provider.Configuration{
			Type: "oidc",
			OIDC: provider.OIDCConfiguration{
				Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
			},
			GitHub: provider.GitHubConfiguration{
				Scopes: []string{"user:email", "read:user"},
			},
		},
	},
	Storage: StorageConfiguration{Type: "local"},
	Session: SessionConfiguration{
		SessionTTL: 24 * time.Hour,
	},
}

type Configuration struct {
	Server     ServerConfiguration     `yaml:"server"`
	Logger     LoggerConfiguration     `yaml:"logger"`
	Prometheus PrometheusConfiguration `yaml:"prometheus"`
	Storage    StorageConfiguration    `yaml:"storage"`
	Authz      AuthzConfiguration      `yaml:"authz"`
	Authn      AuthnConfiguration      `yaml:"authn"`
	Session    SessionConfiguration    `yaml:"session"`
}

func (c Configuration) IsValid() error {
	return errors.Join(
		validate.PrefixError("server", c.Server.IsValid()),
		validate.PrefixError("logger", c.Logger.IsValid()),
		validate.PrefixError("prometheus", c.Prometheus.IsValid()),
		validate.PrefixError("storage", c.Storage.IsValid()),
		validate.PrefixError("authz", c.Authz.IsValid()),
		validate.PrefixError("authn", c.Authn.IsValid()),
		validate.PrefixError("session", c.Session.IsValid()),
	)
}

type ServerConfiguration struct {
	CookieName string `yaml:"cookieName"`
	Key        string `yaml:"key"`
	Domain     string `yaml:"domain"`
	HealthPath string `yaml:"healthPath"`
	AddrInt    string `yaml:"addrInt"`
	AddrExt    string `yaml:"addrExt"`
}

func (c ServerConfiguration) IsValid() error {
	return errors.Join(
		validate.PrefixError("cookieName", validate.IsNotZero(c.CookieName)),
		validate.PrefixError("key", validate.IsMinLength(c.Key, 32)),
		validate.PrefixError("domain", validate.IsNotZero(c.Domain)),
		validate.PrefixError("healthPath", validate.IsAbsolutePath(c.HealthPath)),
		validate.PrefixError("addrInt", validate.IsTCPTarget(c.AddrInt)),
		validate.PrefixError("addrExt", validate.IsTCPTarget(c.AddrExt)),
	)
}

type LoggerConfiguration struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func (c LoggerConfiguration) IsValid() error {
	return errors.Join(
		validate.PrefixError("level", validate.IsEnum(c.Level, "debug", "info", "warn", "error")),
		validate.PrefixError("format", validate.IsEnum(c.Format, "text", "json")),
	)
}

// Logger returns a logger configured with the given configuration.
func (c LoggerConfiguration) Logger(w io.Writer) *slog.Logger {
	var level slog.Level
	err := level.UnmarshalText([]byte(c.Level))
	if err != nil {
		level = slog.LevelInfo
		err = fmt.Errorf("invalid log level: %s. using INFO", c.Level)
	}

	var logger *slog.Logger
	opts := slog.HandlerOptions{Level: level}
	switch strings.ToLower(c.Format) {
	case "text":
		logger = slog.New(slog.NewTextHandler(w, &opts))
	case "json":
		logger = slog.New(slog.NewJSONHandler(w, &opts))
	default:
		logger = slog.New(slog.NewTextHandler(w, &opts))
		err = errors.Join(err, fmt.Errorf("invalid log format: %s. using text", c.Format))
	}

	if err != nil {
		logger.Warn("invalid logger configuration", "err", err)
	}

	return logger
}

type PrometheusConfiguration struct {
	Addr string `yaml:"addr"`
	Path string `yaml:"path"`
}

func (c PrometheusConfiguration) IsValid() error {
	return errors.Join(
		validate.PrefixError("addr", validate.IsTCPTarget(c.Addr)),
		validate.PrefixError("path", validate.IsAbsolutePath(c.Path)),
	)
}

// RunServer runs a prometheus server on the given address.
// The server is shut down when the context is canceled.
func (c PrometheusConfiguration) RunServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle(cmp.Or(c.Path, "/metrics"), promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		// test: reduce memory usage (especially flate.NewWriter() and flate (*compressor) init())
		promhttp.HandlerOpts{DisableCompression: true},
	))
	return httputils.RunServer(ctx, &http.Server{
		Addr:    c.Addr,
		Handler: mux,
	})
}

type AuthnConfiguration struct {
	Provider      provider.Configuration `yaml:"provider"`
	StateTTL      time.Duration          `yaml:"state_ttl"`
	SelectAccount bool                   `yaml:"select_account"`
}

func (c AuthnConfiguration) IsValid() error {
	return errors.Join(
		validate.PrefixError("provider", c.Provider.IsValid()),
		validate.PrefixError("state_ttl", validate.IsNotZero(c.StateTTL)),
	)
}

type AuthzConfiguration struct {
	Rules  []authz.Rule  `yaml:"rules,omitempty"`
	Groups []authz.Group `yaml:"groups,omitempty"`
}

func (c AuthzConfiguration) IsValid() error {
	return nil
}

type StorageConfiguration struct {
	Type  string                    `yaml:"type"`
	Redis StorageRedisConfiguration `yaml:"redis"`
}

func (c StorageConfiguration) IsValid() error {
	errs := validate.PrefixError("type", validate.IsEnum(c.Type, "redis", "local", ""))
	if c.Type == "redis" {
		errs = errors.Join(errs, c.Redis.IsValid())
	}
	return errs
}

type StorageRedisConfiguration struct {
	Addr     string `yaml:"addr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

func (c StorageRedisConfiguration) IsValid() error {
	return validate.PrefixError("addr", errors.Join(validate.IsTCPTarget(c.Addr)))
}

type SessionConfiguration struct {
	SessionTTL time.Duration `yaml:"session_ttl"`
}

func (c SessionConfiguration) IsValid() error {
	return validate.PrefixError("session_ttl", validate.IsNotZero(c.SessionTTL))
}
