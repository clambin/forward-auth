package configuration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"codeberg.org/clambin/go-common/httputils"
	"github.com/clambin/forward-auth/internal/auth"
	"github.com/clambin/forward-auth/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var DefaultConfiguration = Configuration{
	Server:      server.DefaultConfiguration,
	ForwardAuth: auth.DefaultConfiguration,
	Logger: LoggerConfiguration{
		Level:  "info",
		Format: "json",
	},
	Prometheus: PrometheusConfiguration{
		Addr: ":9120",
		Path: "/metrics",
	},
}

type Configuration struct {
	Server      server.Configuration    `yaml:"server"`
	ForwardAuth auth.Configuration      `yaml:"forwardAuth"`
	Logger      LoggerConfiguration     `yaml:"logger"`
	Prometheus  PrometheusConfiguration `yaml:"prometheus"`
}

type LoggerConfiguration struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func (c LoggerConfiguration) Logger() *slog.Logger {
	var level slog.Level
	err := level.UnmarshalText([]byte(c.Level))
	if err != nil {
		level = slog.LevelInfo
		err = fmt.Errorf("invalid log level: %s. using INFO", c.Level)
	}

	var logger *slog.Logger
	switch strings.ToLower(c.Format) {
	case "text":
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	case "json":
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	default:
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
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
