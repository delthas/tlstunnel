package main

import (
	"flag"
	"log"

	"git.sr.ht/~emersion/tlstunnel"
)

var configPath = "config"

func main() {
	flag.StringVar(&configPath, "config", configPath, "path to configuration file")
	flag.Parse()

	cfg, err := tlstunnel.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config file: %v", err)
	}

	srv := tlstunnel.NewServer()

	if err := srv.Load(cfg); err != nil {
		log.Fatal(err)
	}

	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}

	select {}
}
