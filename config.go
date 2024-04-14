package tlstunnel

import (
	"context"
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
	"strings"

	"git.sr.ht/~emersion/go-scfg"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/dnsupdate"

	"log"
)

type serverConfig struct {
	Frontend []frontendConfig `scfg:"frontend"`
	TLS      struct {
		ACMECA         string             `scfg:"acme_ca"`
		Email          string             `scfg:"email"`
		OnDemand       *tlsOnDemandConfig `scfg:"on_demand"`
		ACMEDNSCommand []string           `scfg:"acme_dns_command"`
		ACMEDNSUpdate  string             `scfg:"acme_dns_update"`
	} `scfg:"tls"`
}

type frontendConfig struct {
	Addr   []string `scfg:",param"`
	Listen []struct {
		Addr []string `scfg:",param"`
	} `scfg:"listen"`
	Backend *backendConfig `scfg:"backend"`
	TLS     struct {
		Load *[2]string `scfg:"load"`
	} `scfg:"tls"`
	Protocol []string `scfg:"protocol"`
}

type backendConfig struct {
	URI          string     `scfg:",param"`
	TLSCertFP    *[2]string `scfg:"tls_certfp"`
	ProxyVersion int        `scfg:"proxy_version"`
}

type tlsOnDemandConfig struct {
	ValidateCommand []string `scfg:"validate_command"`
}

func loadConfig(srv *Server, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	var cfg serverConfig
	if err := scfg.NewDecoder(f).Decode(&cfg); err != nil {
		return err
	}
	log.Printf("%#v", cfg)

	for _, feCfg := range cfg.Frontend {
		if err := parseFrontend(srv, &feCfg); err != nil {
			return fmt.Errorf(`directive "frontend": %v`, err)
		}
	}

	srv.ACMEIssuer.CA = cfg.TLS.ACMECA
	srv.ACMEIssuer.Email = cfg.TLS.Email
	if cfg.TLS.ACMEDNSCommand != nil {
		if len(cfg.TLS.ACMEDNSCommand) < 1 {
			return fmt.Errorf(`directive "tls.acme_dns_command": expected at least one parameter`)
		}

		srv.ACMEIssuer.DNS01Solver = &certmagic.DNS01Solver{
			DNSProvider: &commandDNSProvider{
				Name:   cfg.TLS.ACMEDNSCommand[0],
				Params: cfg.TLS.ACMEDNSCommand[1:],
			},
		}
	}
	if addr := cfg.TLS.ACMEDNSUpdate; addr != "" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf(`directive "tls.acme_dns_update": invalid parameter: %v`, err)
		}

		srv.ACMEIssuer.DNS01Solver = &certmagic.DNS01Solver{
			DNSProvider: &dnsupdate.Provider{Addr: addr},
		}
	}
	if cfg.TLS.OnDemand != nil {
		if err := parseTLSOnDemand(srv, cfg.TLS.OnDemand); err != nil {
			return fmt.Errorf(`directive "tls.on_demand": %v`, err)
		}
	}

	return nil
}

func parseFrontend(srv *Server, cfg *frontendConfig) error {
	frontend := &Frontend{}
	srv.Frontends = append(srv.Frontends, frontend)

	// TODO: support multiple backends
	if cfg.Backend == nil {
		return fmt.Errorf("missing backend directive")
	}
	if err := parseBackend(&frontend.Backend, cfg.Backend); err != nil {
		return fmt.Errorf(`directive "backend": %v`, err)
	}

	unmanaged := false
	if cfg.TLS.Load != nil {
		certPath, keyPath := cfg.TLS.Load[0], cfg.TLS.Load[1]

		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return fmt.Errorf(`directive "tls.load": %v`, err)
		}

		srv.UnmanagedCerts = append(srv.UnmanagedCerts, cert)
		unmanaged = true
	}

	frontend.Protocols = cfg.Protocol

	addresses := append([]string(nil), cfg.Addr...)
	for _, listen := range cfg.Listen {
		addresses = append(addresses, listen.Addr...)
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

func parseBackend(backend *Backend, cfg *backendConfig) error {
	if cfg.URI == "" {
		return fmt.Errorf(`expected one parameter`)
	}

	backendURI := cfg.URI
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

	if cfg.TLSCertFP != nil {
		if backend.TLSConfig == nil {
			return fmt.Errorf("tls_certfp requires a tls:// backend address")
		}

		algo, wantCertFP := cfg.TLSCertFP[0], cfg.TLSCertFP[1]
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
	}

	if cfg.ProxyVersion != 0 {
		switch cfg.ProxyVersion {
		case 1, 2:
			backend.ProxyVersion = cfg.ProxyVersion
		default:
			return fmt.Errorf("directive proxy_version: unknown version: %v", cfg.ProxyVersion)
		}
	}

	return nil
}

func parseFrontendTLS(srv *Server, d *scfg.Directive) (unmanaged bool, err error) {
	for _, child := range d.Children {
		switch child.Name {
		case "load":
		default:
			return false, fmt.Errorf("unknown %q directive", child.Name)
		}
	}
	return unmanaged, nil
}

func parseTLSOnDemand(srv *Server, cfg *tlsOnDemandConfig) error {
	if srv.ACMEConfig.OnDemand == nil {
		srv.ACMEConfig.OnDemand = &certmagic.OnDemandConfig{}
	}

	if cfg.ValidateCommand != nil {
		if len(cfg.ValidateCommand) == 0 {
			return fmt.Errorf(`directive "validate_command": expected at least one parameter`)
		}
		cmdName := cfg.ValidateCommand[0]

		decisionFunc := srv.ACMEConfig.OnDemand.DecisionFunc
		srv.ACMEConfig.OnDemand.DecisionFunc = func(ctx context.Context, name string) error {
			if decisionFunc != nil {
				if err := decisionFunc(ctx, name); err != nil {
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

			cmd := exec.CommandContext(ctx, cmdName, cfg.ValidateCommand[1:]...)
			cmd.Env = append(os.Environ(), "TLSTUNNEL_NAME="+name)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to validate domain %q with command %q: %v", name, cmdName, err)
			}

			return nil
		}
	}

	return nil
}
