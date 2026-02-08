package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/stainless-api/stainless-proxy/internal/config"
	"github.com/stainless-api/stainless-proxy/internal/jwe"
	"github.com/stainless-api/stainless-proxy/internal/keystore"
	"github.com/stainless-api/stainless-proxy/internal/proxy"
	"github.com/stainless-api/stainless-proxy/internal/revocation"
	"github.com/stainless-api/stainless-proxy/internal/server"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	if *configPath == "" {
		slog.Error("config flag is required")
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("loading config", "error", err)
		os.Exit(1)
	}

	setupLogging(cfg)

	ks, err := keystore.New(cfg.KeyDir, cfg.GenerateKeys)
	if err != nil {
		slog.Error("initializing keystore", "error", err)
		os.Exit(1)
	}

	primary := ks.PrimaryKey()
	slog.Info("keystore initialized",
		"key_count", len(ks.Keys()),
		"primary_kid", primary.KID,
	)

	var decryptorKeys []jwe.KeyEntry
	for _, k := range ks.Keys() {
		decryptorKeys = append(decryptorKeys, jwe.KeyEntry{
			KID:        k.KID,
			PrivateKey: k.PrivateKey,
		})
	}

	decryptor := jwe.NewMultiKeyDecryptor(decryptorKeys)
	denyList := revocation.NewDenyList()
	p := proxy.New(decryptor, denyList)
	srv := server.New(cfg, ks, p, denyList)

	if err := srv.Run(context.Background()); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func setupLogging(cfg *config.Config) {
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(handler))
}
