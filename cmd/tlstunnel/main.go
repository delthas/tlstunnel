package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"git.sr.ht/~emersion/go-scfg"
	"git.sr.ht/~emersion/tlstunnel"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

var (
	configPath   = "config"
	certDataPath = ""
)

func newServer() (*tlstunnel.Server, error) {
	cfg, err := scfg.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
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
		return nil, fmt.Errorf("failed to initialize zap logger: %w", err)
	}
	srv.ACMEConfig.Logger = logger
	srv.ACMEManager.Logger = logger

	if certDataPath != "" {
		srv.ACMEConfig.Storage = &certmagic.FileStorage{Path: certDataPath}
	}

	if err := srv.Load(cfg); err != nil {
		return nil, err
	}

	return srv, nil
}

func main() {
	flag.StringVar(&configPath, "config", configPath, "path to configuration file")
	flag.Parse()

	srv, err := newServer()
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}

	for sig := range sigCh {
		switch sig {
		case syscall.SIGINT:
		case syscall.SIGTERM:
			srv.Stop()
			return
		case syscall.SIGHUP:
			log.Print("caught SIGHUP, reloading config")
			newSrv, err := newServer()
			if err != nil {
				log.Printf("reload failed: %v", err)
				continue
			}
			err = newSrv.Replace(srv)
			if err != nil {
				log.Printf("reload failed: %v", err)
				continue
			}
			srv = newSrv
			log.Print("successfully reloaded config")
		}
	}
}
