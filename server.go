package tlstunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/pires/go-proxyproto"
)

type Server struct {
	Listeners    map[string]*Listener // indexed by listening address
	Frontends    []*Frontend
	ManagedNames []string
	ACMEManager  *certmagic.ACMEManager
	ACMEConfig   *certmagic.Config
}

func NewServer() *Server {
	cfg := certmagic.NewDefault()

	mgr := certmagic.NewACMEManager(cfg, certmagic.DefaultACME)
	mgr.Agreed = true
	// TODO: enable HTTP challenge by peeking incoming requests on port 80
	mgr.DisableHTTPChallenge = true
	cfg.Issuer = mgr
	cfg.Revoker = mgr

	return &Server{
		Listeners:   make(map[string]*Listener),
		ACMEManager: mgr,
		ACMEConfig:  cfg,
	}
}

func (srv *Server) Load(cfg *Directive) error {
	return parseConfig(srv, cfg)
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
	if err := srv.ACMEConfig.ManageAsync(context.Background(), srv.ManagedNames); err != nil {
		return fmt.Errorf("failed to manage TLS certificates: %v", err)
	}

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
	tlsConn := tls.Server(conn, ln.Server.ACMEConfig.TLSConfig())
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	tlsState := tlsConn.ConnectionState()

	fe, ok := ln.Frontends[tlsState.ServerName]
	if !ok {
		// match wildcard certificates, allowing only a single, non-partial wildcard, in the left-most label
		i := strings.IndexByte(tlsState.ServerName, '.')
		// don't allow wildcards with only a TLD (eg *.com)
		if i >= 0 && strings.IndexByte(tlsState.ServerName[i+1:], '.') >= 0 {
			fe, ok = ln.Frontends["*"+tlsState.ServerName[i:]]
		}
	}
	if !ok {
		fe, ok = ln.Frontends[""]
	}
	if !ok {
		return fmt.Errorf("can't find frontend for server name %q", tlsState.ServerName)
	}

	return fe.handle(tlsConn, &tlsState)
}

type Frontend struct {
	Server  *Server
	Backend Backend
}

func (fe *Frontend) handle(downstream net.Conn, tlsState *tls.ConnectionState) error {
	defer downstream.Close()

	be := &fe.Backend
	upstream, err := net.Dial(be.Network, be.Address)
	if err != nil {
		return fmt.Errorf("failed to dial backend: %v", err)
	}
	defer upstream.Close()

	if be.Proxy {
		h := proxyproto.HeaderProxyFromAddrs(2, downstream.RemoteAddr(), downstream.LocalAddr())

		var tlvs []proxyproto.TLV
		if tlsState.ServerName != "" {
			tlvs = append(tlvs, authorityTLV(tlsState.ServerName))
		}
		if err := h.SetTLVs(tlvs); err != nil {
			return fmt.Errorf("failed to set PROXY protocol header TLVs: %v", err)
		}

		if _, err := h.WriteTo(upstream); err != nil {
			return fmt.Errorf("failed to write PROXY protocol header: %v", err)
		}
	}

	return duplexCopy(upstream, downstream)
}

type Backend struct {
	Network string
	Address string
	Proxy   bool
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

func authorityTLV(name string) proxyproto.TLV {
	return proxyproto.TLV{
		Type:   proxyproto.PP2_TYPE_AUTHORITY,
		Length: len(name),
		Value:  []byte(name),
	}
}
