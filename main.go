package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
)

func main() {
	cfg, err := Load("config")
	if err != nil {
		log.Fatalf("failed to load config file: %v", err)
	}

	srv := NewServer()

	for _, d := range cfg.ChildrenByName("frontend") {
		if err := parseFrontend(srv, d); err != nil {
			log.Fatalf("failed to parse frontend: %v", err)
		}
	}

	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}

	select {}
}

func parseFrontend(srv *Server, d *Directive) error {
	frontend := &Frontend{Server: srv}
	srv.Frontends = append(srv.Frontends, frontend)

	// TODO: support multiple backends
	backendDirective := d.ChildByName("backend")
	if backendDirective == nil {
		return fmt.Errorf("missing backend directive in frontend block")
	}
	if err := parseBackend(&frontend.Backend, backendDirective); err != nil {
		return err
	}

	var listenNames []string
	for _, listenAddr := range d.Params {
		host, port, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return fmt.Errorf("failed to parse listen address %q: %v", listenAddr, err)
		}

		// TODO: come up with something more robust
		var name string
		if host != "localhost" && net.ParseIP(host) == nil {
			name = host
			listenNames = append(listenNames, host)
			host = ""
		}

		addr := net.JoinHostPort(host, port)

		ln := srv.RegisterListener(addr)
		if err := ln.RegisterFrontend(name, frontend); err != nil {
			return err
		}
	}

	if err := srv.certmagic.ManageAsync(context.Background(), listenNames); err != nil {
		return fmt.Errorf("failed to manage TLS certificates: %v", err)
	}

	return nil
}

func parseBackend(backend *Backend, d *Directive) error {
	var backendURI string
	if err := d.ParseParams(&backendURI); err != nil {
		return err
	}
	if !strings.Contains(backendURI, ":/") {
		// This is a raw domain name, make it an URL with an empty scheme
		backendURI = "//" + backendURI
	}

	u, err := url.Parse(backendURI)
	if err != nil {
		return fmt.Errorf("failed to parse backend URI %q: %v", backendURI, err)
	}

	// TODO: +proxy to use the PROXY protocol

	switch u.Scheme {
	case "", "tcp":
		backend.Network = "tcp"
		backend.Address = u.Host
	case "unix":
		backend.Network = "unix"
		backend.Address = u.Host
	default:
		return fmt.Errorf("failed to setup backend %q: unsupported URI scheme", backendURI)
	}

	return nil
}
