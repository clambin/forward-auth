package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"codeberg.org/clambin/go-common/httputils"
	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authz"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/observability"
	"github.com/clambin/forward-auth/internal/server"
	"github.com/clambin/forward-auth/internal/server/healthcheck"
	"github.com/clambin/forward-auth/internal/session"
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

	if len(cfg.Server.Key) < 32 {
		logger.Error("token key must be at least 32 characters long")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	authenticator, err := authn.New(ctx, cfg)
	if err != nil {
		logger.Error("failed to create authenticator", "err", err)
		os.Exit(1)
	}

	authorizer := &authz.Authorizer{Rules: cfg.Authz.Rules, Groups: cfg.Authz.Groups}

	handler, err := session.New(cfg.Session.SessionTTL, cfg.Server, cfg.Storage, authenticator, logger.With("component", "sessions"))
	if err != nil {
		logger.Error("failed to create token manager cache", "err", err)
		os.Exit(1)
	}

	var redisClient healthcheck.RedisClient
	if cfg.Storage.Type == "redis" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Storage.Redis.Addr,
			Username: cfg.Storage.Redis.Username,
			Password: cfg.Storage.Redis.Password,
			DB:       cfg.Storage.Redis.DB,
		})
		defer func() { _ = redisClient.Close() }()
	}

	logger.Info("starting forward-auth", "version", version)

	metrics := observability.GetMetrics()
	prometheus.MustRegister(
		metrics,
		observability.InstrumentedStore{
			Store: handler,
			Desc: prometheus.NewDesc(
				"forward_auth_session_count",
				"Number of active sessions",
				nil,
				nil,
			),
		},
		observability.InstrumentedStore{
			Store: authenticator,
			Desc: prometheus.NewDesc(
				"forward_auth_state_count",
				"Number of active states",
				nil,
				nil,
			),
		},
	)

	hInt, hExt := server.New(
		cfg.Server,
		handler,
		authorizer,
		metrics,
		healthcheck.Handler(redisClient, logger.With("component", "healthcheck")),
		logger,
	)

	var g errgroup.Group
	// Prometheus
	g.Go(func() error {
		return cfg.Prometheus.RunServer(ctx)
	})
	// Internal handlers
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{
			Addr:    cfg.Server.AddrInt,
			Handler: hInt,
		})
	})
	// External handlers
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{
			Addr:    cfg.Server.AddrExt,
			Handler: hExt,
		})
	})
	// pprof
	g.Go(func() error {
		return httputils.RunServer(ctx, &http.Server{
			Addr:    ":6060",
			Handler: http.DefaultServeMux,
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
