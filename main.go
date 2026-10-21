package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
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
	"github.com/sethvargo/go-envconfig/v2"
	"golang.org/x/sync/errgroup"
)

var (
	version = "(devel)"
	config  = flag.String("config", "/etc/forward-auth/config.yaml", "path to config file")
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	flag.Parse()
	cfg, err := getConfiguration(ctx)
	if err != nil {
		panic(fmt.Errorf("failed to read configuration: %w", err))
	}
	if err = cfg.IsValid(); err != nil {
		panic(fmt.Errorf("invalid configuration: %w", err))
	}

	logger := cfg.Logger.Logger(os.Stderr)
	logger.Debug("debug is ON")

	authenticator, err := authn.New(ctx, cfg)
	if err != nil {
		logger.Error("failed to create authenticator", "err", err)
		os.Exit(1)
	}

	authorizer := &authz.Authorizer{Rules: cfg.Authz.Rules, Groups: cfg.Authz.Groups}

	handler, err := session.New(cfg.Session.TTL, cfg.Server, cfg.Storage, authenticator, logger.With("component", "sessions"))
	if err != nil {
		logger.Error("failed to create token manager cache", "err", err)
		os.Exit(1)
	}

	var redisClient *redis.Client
	if strings.EqualFold(cfg.Storage.Type, "redis") {
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
	if err = g.Wait(); err != nil {
		logger.Error("failed to start server(s)", "err", err)
	}
}

func getConfiguration(ctx context.Context) (configuration.Configuration, error) {
	// start from the default configuration
	cfg := configuration.Default()

	// override from the configuration file stored on disk
	f, err := os.Open(*config)
	if err != nil {
		return cfg, fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err = yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("failed to decode config file: %w", err)
	}

	// override from environment variables
	err = envconfig.ProcessWith(ctx, &envconfig.Config{
		Target:           &cfg,
		Lookuper:         envconfig.OsLookuper(),
		DefaultOverwrite: true,
	})
	if err != nil {
		return cfg, fmt.Errorf("failed to process environment variables: %w", err)
	}
	return cfg, nil
}
