package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
)

var configPath = "config"

func main() {
	flag.StringVar(&configPath, "config", configPath, "path to configuration file")
	flag.Parse()

	cfg, err := Load(configPath)
	if err != nil {
		log.Fatalf("failed to load config file: %v", err)
	}

	srv := NewServer()

	for _, d := range cfg.Children {
		var err error
		switch d.Name {
		case "frontend":
			err = parseFrontend(srv, d)
		case "tls":
			err = parseTLS(srv, d)
		default:
			log.Fatalf("unknown %q directive", d.Name)
		}
		if err != nil {
			log.Fatalf("directive %q: %v", d.Name, err)
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

	for _, listenAddr := range d.Params {
		host, port, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return fmt.Errorf("failed to parse listen address %q: %v", listenAddr, err)
		}

		// TODO: come up with something more robust
		var name string
		if host != "" && host != "localhost" && net.ParseIP(host) == nil {
			name = host
			host = ""

			srv.ManagedNames = append(srv.ManagedNames, name)
		}

		addr := net.JoinHostPort(host, port)

		ln := srv.RegisterListener(addr)
		if err := ln.RegisterFrontend(name, frontend); err != nil {
			return err
		}
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

	if strings.HasSuffix(u.Scheme, "+proxy") {
		u.Scheme = strings.TrimSuffix(u.Scheme, "+proxy")
		backend.Proxy = true
	}

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

func parseTLS(srv *Server, d *Directive) error {
	for _, child := range d.Children {
		switch child.Name {
		case "ca":
			var caURL string
			if err := child.ParseParams(&caURL); err != nil {
				return err
			}
			srv.acmeManager.CA = caURL
		default:
			return fmt.Errorf("unknown %q directive", child.Name)
		}
	}
	return nil
}
