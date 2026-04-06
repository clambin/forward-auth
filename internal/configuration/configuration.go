package configuration

import (
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var DefaultConfiguration = Configuration{
	Server: ServerConfiguration{
		Addr:       ":8080",
		CookieName: "forward-auth-session",
	},
	Logger: LoggerConfiguration{
		Level:  "info",
		Format: "json",
	},
	Prometheus: PrometheusConfiguration{
		Addr: ":9120",
		Path: "/metrics",
	},
	Authn: AuthnConfiguration{
		StateTTL: 10 * time.Minute,
		Provider: provider.Configuration{Type: "google"},
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
	Authz      AuthzConfiguration      `yaml:"authz"`
	Authn      AuthnConfiguration      `yaml:"authn"`
	Storage    StorageConfiguration    `yaml:"storage"`
	Session    SessionConfiguration    `yaml:"session"`
}

type ServerConfiguration struct {
	Addr       string `yaml:"addr"`
	CookieName string `yaml:"cookieName"`
	Domain     string `yaml:"domain"`
}

type LoggerConfiguration struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

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

func (c PrometheusConfiguration) RunServer(ctx context.Context, g prometheus.Gatherer) error {
	h := promhttp.Handler()
	if g != nil {
		h = promhttp.HandlerFor(g, promhttp.HandlerOpts{})
	}
	return httputils.RunServer(ctx, &http.Server{
		Addr:    c.Addr,
		Handler: h,
	})
}

type AuthnConfiguration struct {
	Provider provider.Configuration `yaml:"provider"`
	StateTTL time.Duration          `yaml:"state_ttl"`
}

type AuthzConfiguration struct {
	Rules []authz.Rule `yaml:"rules"`
}

type StorageConfiguration struct {
	Type  string                    `yaml:"type"`
	Redis StorageRedisConfiguration `yaml:"redis"`
}

type StorageRedisConfiguration struct {
	Addr     string `yaml:"addr"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type SessionConfiguration struct {
	SessionTTL time.Duration `yaml:"session_ttl"`
}
