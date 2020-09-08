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
	Frontends []*Frontend
	certmagic *certmagic.Config
}

func NewServer() *Server {
	cfg := certmagic.NewDefault()

	acme := certmagic.DefaultACME
	acme.CA = certmagic.LetsEncryptStagingCA
	acme.Agreed = true
	// TODO: enable HTTP challenge by peeking incoming requests on port 80
	acme.DisableHTTPChallenge = true
	mgr := certmagic.NewACMEManager(cfg, acme)
	cfg.Issuer = mgr
	cfg.Revoker = mgr

	return &Server{certmagic: cfg}
}

type Frontend struct {
	Server  *Server
	Backend Backend
}

func (fe *Frontend) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		conn = tls.Server(conn, fe.Server.certmagic.TLSConfig())

		go func() {
			if err := fe.handle(conn); err != nil {
				log.Printf("error handling connection: %v", err)
			}
		}()
	}
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
