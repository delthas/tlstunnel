package tlstunnel

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	"git.sr.ht/~emersion/go-scfg"
)

func parseConfig(srv *Server, cfg scfg.Block) error {
	for _, d := range cfg {
		var err error
		switch d.Name {
		case "frontend":
			err = parseFrontend(srv, d)
		case "tls":
			err = parseTLS(srv, d)
		default:
			return fmt.Errorf("unknown %q directive", d.Name)
		}
		if err != nil {
			return fmt.Errorf("directive %q: %v", d.Name, err)
		}
	}
	return nil
}

func parseFrontend(srv *Server, d *scfg.Directive) error {
	frontend := &Frontend{Server: srv}
	srv.Frontends = append(srv.Frontends, frontend)

	// TODO: support multiple backends
	backendDirective := d.Children.Get("backend")
	if backendDirective == nil {
		return fmt.Errorf("missing backend directive in frontend block")
	}
	if err := parseBackend(&frontend.Backend, backendDirective); err != nil {
		return err
	}

	unmanaged := false
	tlsDirective := d.Children.Get("tls")
	if tlsDirective != nil {
		var err error
		unmanaged, err = parseFrontendTLS(srv, tlsDirective)
		if err != nil {
			return err
		}
	}

	for _, addr := range d.Params {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("failed to parse frontend address %q: %v", addr, err)
		}

		if host != "" && !unmanaged {
			srv.ManagedNames = append(srv.ManagedNames, host)
		}

		// TODO: allow to customize listen host
		addr := net.JoinHostPort("", port)

		ln := srv.RegisterListener(addr)
		if err := ln.RegisterFrontend(host, frontend); err != nil {
			return err
		}
	}

	return nil
}

func parseBackend(backend *Backend, d *scfg.Directive) error {
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
	case "tls":
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			return fmt.Errorf("failed to parse backend address %q: %v", u.Host, err)
		}
		backend.TLSConfig = &tls.Config{
			ServerName: host,
		}
		fallthrough
	case "", "tcp":
		backend.Network = "tcp"
		backend.Address = u.Host
	case "unix":
		backend.Network = "unix"
		backend.Address = u.Path
	default:
		return fmt.Errorf("failed to setup backend %q: unsupported URI scheme", backendURI)
	}

	return nil
}

func parseFrontendTLS(srv *Server, d *scfg.Directive) (unmanaged bool, err error) {
	for _, child := range d.Children {
		switch child.Name {
		case "load":
			var certPath, keyPath string
			if err := child.ParseParams(&certPath, &keyPath); err != nil {
				return false, err
			}

			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return false, fmt.Errorf("directive \"load\": %v", err)
			}

			srv.UnmanagedCerts = append(srv.UnmanagedCerts, cert)
			unmanaged = true
		default:
			return false, fmt.Errorf("unknown %q directive", child.Name)
		}
	}
	return unmanaged, nil
}

func parseTLS(srv *Server, d *scfg.Directive) error {
	for _, child := range d.Children {
		switch child.Name {
		case "acme_ca":
			var caURL string
			if err := child.ParseParams(&caURL); err != nil {
				return err
			}
			srv.ACMEManager.CA = caURL
		case "email":
			var email string
			if err := child.ParseParams(&email); err != nil {
				return err
			}
			srv.ACMEManager.Email = email
		default:
			return fmt.Errorf("unknown %q directive", child.Name)
		}
	}
	return nil
}
