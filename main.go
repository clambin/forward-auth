package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"codeberg.org/clambin/go-common/httputils"
	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/server"
	"github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

var (
	version = "(devel)"
	config  = flag.String("config", "/etc/forward-auth/config.yaml", "path to config file")
)

func main() {
	flag.Parse()
	cfg, err := getConfiguration()
	if err != nil {
		panic(err)
	}
	logger := cfg.Logger.Logger(os.Stderr)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	authenticator, err := authn.New(ctx, cfg.Authn)
	if err != nil {
		logger.Error("failed to create authenticator", "err", err)
		os.Exit(1)
	}

	authorizer, err := authz.New(cfg.Authz.Rules)
	if err != nil {
		logger.Error("failed to create authorizer", "err", err)
		os.Exit(1)
	}

	var redisClient server.RedisClient
	if cfg.Authn.Storage.Type == "redis" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Authn.Storage.Redis.Addr,
			Username: cfg.Authn.Storage.Redis.Username,
			Password: cfg.Authn.Storage.Redis.Password,
			DB:       cfg.Authn.Storage.Redis.DB,
		})
	}

	logger.Info("starting forward-auth", "version", version)

	metrics := server.GetMetrics()
	prometheus.MustRegister(metrics)

	var g errgroup.Group
	// Prometheus
	g.Go(func() error {
		return cfg.Prometheus.RunServer(ctx, nil)
	})
	// forward-auth
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{
			Addr:    cfg.Server.Addr,
			Handler: server.New(cfg.Server, authenticator, authorizer, redisClient, metrics, logger),
		})
	})
	if err = g.Wait(); err != nil {
		logger.Error("failed to start server(s)", "err", err)
	}
}

func getConfiguration() (configuration.Configuration, error) {
	cfg := configuration.DefaultConfiguration
	b, err := os.ReadFile(*config)
	if errors.Is(err, os.ErrNotExist) {
		cfg.Logger.Logger(os.Stderr).Warn("no config file found, using default configuration")
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}

	buf := strings.NewReader(os.ExpandEnv(string(b)))

	if err = yaml.NewDecoder(buf).Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, err
}
