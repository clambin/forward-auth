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
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/configuration/validate"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func Default() Configuration {
	return Configuration{
		Server: ServerConfiguration{
			CookieName: "forward-auth-session",
			Key:        "",
			HealthPath: "/healthz",
			AddrInt:    ":8080",
			AddrExt:    ":8081",
		},
		Logger: LoggerConfiguration{
			Level:  slog.LevelInfo,
			Format: "text",
		},
		Prometheus: PrometheusConfiguration{
			Addr: ":9120",
			Path: "/metrics",
		},
		Authn: AuthnConfiguration{
			StateTTL: 10 * time.Minute,
			Provider: ProviderConfiguration{
				Type: "oidc",
				OIDC: OIDCProviderConfiguration{
					Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
				},
				GitHub: GitHubProviderConfiguration{
					Scopes: []string{"user:email", "read:user"},
				},
			},
			SelectAccount: true,
		},
		Storage: StorageConfiguration{Type: "local"},
		Session: SessionConfiguration{
			TTL: 24 * time.Hour,
		},
	}
}

type Configuration struct {
	Server     ServerConfiguration     `yaml:"server" env:", prefix=SERVER_"`
	Logger     LoggerConfiguration     `yaml:"logger" env:", prefix=LOGGER_"`
	Prometheus PrometheusConfiguration `yaml:"prometheus" env:", prefix=PROMETHEUS_"`
	Storage    StorageConfiguration    `yaml:"storage" env:", prefix=STORAGE_"`
	Authz      AuthzConfiguration      `yaml:"authz"`
	Authn      AuthnConfiguration      `yaml:"authn" env:", prefix=AUTHN_"`
	Session    SessionConfiguration    `yaml:"session" env:", prefix=SESSION_"`
}

func (c Configuration) IsValid() error {
	return validate.IsValid(c)
}

type ServerConfiguration struct {
	CookieName string `yaml:"cookieName"`
	Key        string `yaml:"key" env:"KEY"`
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
		validate.PrefixError("addrInt", validate.IsTCPListener(c.AddrInt)),
		validate.PrefixError("addrExt", validate.IsTCPListener(c.AddrExt)),
	)
}

type LoggerConfiguration struct {
	Level  slog.Level `yaml:"level"`
	Format string     `yaml:"format"`
}

func (c LoggerConfiguration) IsValid() error {
	return errors.Join(
		// don't need to validate Level, as it's already validated during unmarshaling
		validate.PrefixError("format", validate.IsEnum(c.Format, "text", "json")),
	)
}

// Logger returns a logger configured with the given configuration.
func (c LoggerConfiguration) Logger(w io.Writer) *slog.Logger {
	var logger *slog.Logger
	opts := slog.HandlerOptions{Level: c.Level}
	var err error
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
		validate.PrefixError("addr", validate.IsTCPListener(c.Addr)),
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
	Provider      ProviderConfiguration `yaml:"provider" env:", prefix=PROVIDER_"`
	StateTTL      time.Duration         `yaml:"state_ttl"`
	SelectAccount bool                  `yaml:"select_account"`
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
	Redis StorageRedisConfiguration `yaml:"redis" env:", prefix=REDIS_"`
}

func (c StorageConfiguration) IsValid() error {
	errs := validate.PrefixError("type", validate.IsEnum(c.Type, "redis", "local", ""))
	if strings.EqualFold(c.Type, "redis") {
		errs = errors.Join(errs, c.Redis.IsValid())
	}
	return errs
}

type StorageRedisConfiguration struct {
	Addr     string `yaml:"addr"`
	Username string `yaml:"username" env:"USERNAME"`
	Password string `yaml:"password" env:"PASSWORD"`
	DB       int    `yaml:"db"`
}

func (c StorageRedisConfiguration) IsValid() error {
	return validate.PrefixError("addr", errors.Join(validate.IsTCPTarget(c.Addr)))
}

type ProviderConfiguration struct {
	Type        string                      `yaml:"type"`
	RedirectURL string                      `yaml:"redirect_url"`
	OIDC        OIDCProviderConfiguration   `yaml:"oidc" env:", prefix=OIDC_"`
	GitHub      GitHubProviderConfiguration `yaml:"github" env:", prefix=GITHUB_"`
}

func (c ProviderConfiguration) IsValid() error {
	errs := errors.Join(
		validate.PrefixError("type", validate.IsEnum(c.Type, "oidc", "github")),
		validate.PrefixError("redirect_url", validate.IsNotZero(c.RedirectURL)),
	)
	switch strings.ToLower(c.Type) {
	case "oidc":
		errs = errors.Join(errs, validate.PrefixError("oidc", c.OIDC.IsValid()))
	case "github":
		errs = errors.Join(errs, validate.PrefixError("github", c.GitHub.IsValid()))
	}
	return errs
}

type OIDCProviderConfiguration struct {
	IssuerURL    string   `yaml:"issuer_url"`
	ClientID     string   `yaml:"client_id" env:"CLIENT_ID"`
	ClientSecret string   `yaml:"client_secret" env:"CLIENT_SECRET"`
	Scopes       []string `yaml:"scopes"`
}

func (c OIDCProviderConfiguration) IsValid() error {
	return errors.Join(
		validate.PrefixError("issuer_url", validate.IsNotZero(c.IssuerURL)),
		validate.PrefixError("client_id", validate.IsNotZero(c.ClientID)),
		validate.PrefixError("client_secret", validate.IsNotZero(c.ClientSecret)),
	)
}

type GitHubProviderConfiguration struct {
	ClientID     string   `yaml:"client_id" env:"CLIENT_ID"`
	ClientSecret string   `yaml:"client_secret" env:"CLIENT_SECRET"`
	Scopes       []string `yaml:"scopes"`
}

func (c GitHubProviderConfiguration) IsValid() error {
	return errors.Join(
		validate.PrefixError("client_id", validate.IsNotZero(c.ClientID)),
		validate.PrefixError("client_secret", validate.IsNotZero(c.ClientSecret)),
	)
}

type SessionConfiguration struct {
	TTL time.Duration `yaml:"session_ttl"`
}

func (c SessionConfiguration) IsValid() error {
	return validate.PrefixError("session_ttl", validate.IsNotZero(c.TTL))
}
