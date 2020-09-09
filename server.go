package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/caddyserver/certmagic"
)

type Server struct {
	Listeners map[string]*Listener // indexed by listening address
	Frontends []*Frontend
	certmagic *certmagic.Config
}

func NewServer() *Server {
	cfg := certmagic.NewDefault()

	acme := certmagic.DefaultACME
	// TODO: use production CA
	acme.CA = certmagic.LetsEncryptStagingCA
	acme.Agreed = true
	// TODO: enable HTTP challenge by peeking incoming requests on port 80
	acme.DisableHTTPChallenge = true
	mgr := certmagic.NewACMEManager(cfg, acme)
	cfg.Issuer = mgr
	cfg.Revoker = mgr

	return &Server{
		Listeners: make(map[string]*Listener),
		certmagic: cfg,
	}
}

func (srv *Server) RegisterListener(addr string) *Listener {
	// TODO: normalize addr with net.LookupPort
	ln, ok := srv.Listeners[addr]
	if !ok {
		ln = newListener(srv, addr)
		srv.Listeners[addr] = ln
	}
	return ln
}

func (srv *Server) Start() error {
	for _, ln := range srv.Listeners {
		if err := ln.Start(); err != nil {
			return err
		}
	}
	return nil
}

type Listener struct {
	Address   string
	Server    *Server
	Frontends map[string]*Frontend // indexed by server name
}

func newListener(srv *Server, addr string) *Listener {
	return &Listener{
		Address:   addr,
		Server:    srv,
		Frontends: make(map[string]*Frontend),
	}
}

func (ln *Listener) RegisterFrontend(name string, fe *Frontend) error {
	if _, ok := ln.Frontends[name]; ok {
		return fmt.Errorf("listener %q: duplicate frontends for server name %q", ln.Address, name)
	}
	ln.Frontends[name] = fe
	return nil
}

func (ln *Listener) Start() error {
	netLn, err := net.Listen("tcp", ln.Address)
	if err != nil {
		return err
	}
	log.Printf("listening on %q", ln.Address)

	go func() {
		if err := ln.serve(netLn); err != nil {
			log.Fatalf("listener %q: %v", ln.Address, err)
		}
	}()

	return nil
}

func (ln *Listener) serve(netLn net.Listener) error {
	for {
		conn, err := netLn.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go func() {
			if err := ln.handle(conn); err != nil {
				log.Printf("listener %q: %v", ln.Address, err)
			}
		}()
	}
}

func (ln *Listener) handle(conn net.Conn) error {
	defer conn.Close()

	// TODO: setup timeouts
	tlsConn := tls.Server(conn, ln.Server.certmagic.TLSConfig())
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	tlsState := tlsConn.ConnectionState()

	// TODO: support wildcard certificates. Sadly this requires solving a DNS
	// challenge.
	fe, ok := ln.Frontends[tlsState.ServerName]
	if !ok {
		fe, ok = ln.Frontends[""]
	}
	if !ok {
		return fmt.Errorf("can't find frontend for server name %q", tlsState.ServerName)
	}

	return fe.handle(tlsConn)
}

type Frontend struct {
	Server  *Server
	Backend Backend
}

func (fe *Frontend) handle(downstream net.Conn) error {
	defer downstream.Close()

	be := &fe.Backend
	upstream, err := net.Dial(be.Network, be.Address)
	if err != nil {
		return fmt.Errorf("failed to dial backend: %v", err)
	}
	defer upstream.Close()

	return duplexCopy(upstream, downstream)
}

type Backend struct {
	Network string
	Address string
}

func duplexCopy(a, b io.ReadWriter) error {
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(a, b)
		done <- err
	}()
	go func() {
		_, err := io.Copy(b, a)
		done <- err
	}()
	return <-done
}
