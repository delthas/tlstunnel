package tlstunnel

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"git.sr.ht/~emersion/go-scfg"
	"github.com/caddyserver/certmagic"
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
	frontend := &Frontend{}
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

	protocolDirective := d.Children.Get("protocol")
	if protocolDirective != nil {
		frontend.Protocols = protocolDirective.Params
	}

	addresses := append([]string(nil), d.Params...)
	for _, listenDirective := range d.Children.GetAll("listen") {
		addresses = append(addresses, listenDirective.Params...)
	}

	if len(addresses) == 0 {
		return fmt.Errorf("missing listening addresses in frontend block")
	}

	for _, addr := range addresses {
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

	for _, child := range d.Children {
		switch child.Name {
		case "tls_certfp":
			if backend.TLSConfig == nil {
				return fmt.Errorf("tls_certfp requires a tls:// backend address")
			}

			var algo, wantCertFP string
			if err := child.ParseParams(&algo, &wantCertFP); err != nil {
				return err
			}
			if algo != "sha-256" {
				return fmt.Errorf("directive tls_certfp: only sha-256 is supported")
			}

			wantCertFP = strings.ReplaceAll(wantCertFP, ":", "")
			wantSum, err := hex.DecodeString(wantCertFP)
			if err != nil {
				return fmt.Errorf("directive tls_certfp: invalid fingerprint: %v", err)
			} else if len(wantSum) != sha256.Size {
				return fmt.Errorf("directive tls_certfp: invalid fingerprint length")
			}

			backend.TLSConfig.InsecureSkipVerify = true
			backend.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("the server didn't present any TLS certificate")
				}

				for _, rawCert := range rawCerts {
					sum := sha256.Sum256(rawCert)
					if subtle.ConstantTimeCompare(sum[:], wantSum) == 1 {
						return nil // fingerprints match
					}
				}

				sum := sha256.Sum256(rawCerts[0])
				remoteCertFP := hex.EncodeToString(sum[:])
				return fmt.Errorf("configured TLS certificate fingerprint doesn't match the server's - %s", remoteCertFP)
			}
		case "proxy_version":
			var version string
			if err := child.ParseParams(&version); err != nil {
				return err
			}
			v, err := strconv.Atoi(version)
			if err != nil {
				return fmt.Errorf("directive proxy_version: invalid version: %v", err)
			}
			switch v {
			case 1, 2:
			default:
				return fmt.Errorf("directive proxy_version: unknown version: %v", v)
			}
			backend.ProxyVersion = v
		}
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
			srv.ACMEIssuer.CA = caURL
		case "email":
			var email string
			if err := child.ParseParams(&email); err != nil {
				return err
			}
			srv.ACMEIssuer.Email = email
		case "on_demand":
			if err := parseTLSOnDemand(srv, child); err != nil {
				return err
			}
		case "acme_dns_command":
			var cmdName string
			if err := child.ParseParams(&cmdName); err != nil {
				return err
			}
			cmdParams := child.Params[1:]

			srv.ACMEIssuer.DNS01Solver = &certmagic.DNS01Solver{
				DNSProvider: &commandDNSProvider{
					Name:   cmdName,
					Params: cmdParams,
				},
			}
		default:
			return fmt.Errorf("unknown %q directive", child.Name)
		}
	}
	return nil
}

func parseTLSOnDemand(srv *Server, d *scfg.Directive) error {
	if srv.ACMEConfig.OnDemand == nil {
		srv.ACMEConfig.OnDemand = &certmagic.OnDemandConfig{}
	}

	for _, child := range d.Children {
		switch child.Name {
		case "validate_command":
			var cmdName string
			if err := child.ParseParams(&cmdName); err != nil {
				return err
			}
			decisionFunc := srv.ACMEConfig.OnDemand.DecisionFunc
			srv.ACMEConfig.OnDemand.DecisionFunc = func(name string) error {
				if decisionFunc != nil {
					if err := decisionFunc(name); err != nil {
						return err
					}
				}

				// If the user has explicitly requested a certificate for this
				// name to be maintained, no need to perform the command check
				for _, n := range srv.ManagedNames {
					if strings.EqualFold(n, name) {
						return nil
					}
				}

				cmd := exec.Command(cmdName, child.Params[1:]...)
				cmd.Env = append(os.Environ(), "TLSTUNNEL_NAME="+name)
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to validate domain %q with command %q: %v", name, cmdName, err)
				}

				return nil
			}
		default:
			return fmt.Errorf("unknown %q directive", child.Name)
		}
	}

	return nil
}
