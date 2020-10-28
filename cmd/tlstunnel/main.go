package main

import (
	"flag"
	"log"

	"git.sr.ht/~emersion/go-scfg"
	"git.sr.ht/~emersion/tlstunnel"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

var (
	configPath   = "config"
	certDataPath = ""
)

func main() {
	flag.StringVar(&configPath, "config", configPath, "path to configuration file")
	flag.Parse()

	cfg, err := scfg.Load(configPath)
	if err != nil {
		log.Fatalf("failed to load config file: %v", err)
	}

	srv := tlstunnel.NewServer()

	loggerCfg := zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.InfoLevel),
		Encoding:          "console",
		EncoderConfig:     zap.NewDevelopmentEncoderConfig(),
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
		DisableStacktrace: true,
		DisableCaller:     true,
	}
	logger, err := loggerCfg.Build()
	if err != nil {
		log.Fatalf("failed to initialize zap logger: %v", err)
	}
	srv.ACMEConfig.Logger = logger
	srv.ACMEManager.Logger = logger

	if certDataPath != "" {
		srv.ACMEConfig.Storage = &certmagic.FileStorage{Path: certDataPath}
	}

	if err := srv.Load(cfg); err != nil {
		log.Fatal(err)
	}

	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}

	select {}
}
