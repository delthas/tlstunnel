package main

import (
	"flag"
	"log"

	"git.sr.ht/~emersion/tlstunnel"
	"github.com/caddyserver/certmagic"
)

var (
	configPath   = "config"
	certDataPath = ""
)

func main() {
	flag.StringVar(&configPath, "config", configPath, "path to configuration file")
	flag.Parse()

	cfg, err := tlstunnel.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config file: %v", err)
	}

	srv := tlstunnel.NewServer()

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
