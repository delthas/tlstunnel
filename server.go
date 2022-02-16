package tlstunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/pires/go-proxyproto"
	"github.com/pires/go-proxyproto/tlvparse"
)

const tlsHandshakeTimeout = 20 * time.Second

type acmeCache struct {
	config atomic.Value
	cache  *certmagic.Cache
}

func newACMECache() *acmeCache {
	cache := &acmeCache{}
	cache.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return cache.config.Load().(*certmagic.Config), nil
		},
	})
	return cache
}

type Server struct {
	Listeners map[string]*Listener // indexed by listening address
	Frontends []*Frontend
	Debug     bool

	ManagedNames   []string
	UnmanagedCerts []tls.Certificate

	ACMEIssuer *certmagic.ACMEIssuer
	ACMEConfig *certmagic.Config

	acmeCache       *acmeCache
	cancelACME      context.CancelFunc
	unmanagedHashes []string
}

func NewServer() *Server {
	// Make a copy of the defaults
	acmeConfig := certmagic.Default
	acmeManager := certmagic.DefaultACME

	acmeManager.Agreed = true
	// We're a TLS server, we don't speak HTTP
	acmeManager.DisableHTTPChallenge = true

	return &Server{
		Listeners:  make(map[string]*Listener),
		ACMEIssuer: &acmeManager,
		ACMEConfig: &acmeConfig,
	}
}

func (srv *Server) Load(filename string) error {
	return loadConfig(srv, filename)
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

func (srv *Server) startACME() error {
	var ctx context.Context
	ctx, srv.cancelACME = context.WithCancel(context.Background())

	srv.ACMEConfig = certmagic.New(srv.acmeCache.cache, *srv.ACMEConfig)
	srv.ACMEIssuer = certmagic.NewACMEIssuer(srv.ACMEConfig, *srv.ACMEIssuer)

	srv.ACMEConfig.Issuers = []certmagic.Issuer{srv.ACMEIssuer}

	srv.acmeCache.config.Store(srv.ACMEConfig)

	for _, cert := range srv.UnmanagedCerts {
		hash, err := srv.ACMEConfig.CacheUnmanagedTLSCertificate(ctx, cert, nil)
		if err != nil {
			return fmt.Errorf("failed to cache unmanaged TLS certificate: %v", err)
		}
		srv.unmanagedHashes = append(srv.unmanagedHashes, hash)
	}

	if err := srv.ACMEConfig.ManageAsync(ctx, srv.ManagedNames); err != nil {
		return fmt.Errorf("failed to manage TLS certificates: %v", err)
	}

	return nil
}

func (srv *Server) Start() error {
	srv.acmeCache = newACMECache()

	if err := srv.startACME(); err != nil {
		return err
	}

	for _, ln := range srv.Listeners {
		if err := ln.Start(); err != nil {
			return fmt.Errorf("failed to start listener: %v", err)
		}
	}
	return nil
}

func (srv *Server) Stop() {
	srv.cancelACME()
	for addr, ln := range srv.Listeners {
		if err := ln.Stop(); err != nil {
			log.Printf("listener %q: failed to stop: %v", addr, err)
		}
	}
	srv.acmeCache.cache.Stop()
}

// Replace starts the server but takes over existing listeners from an old
// Server instance. The old instance keeps running unchanged if Replace
// returns an error.
func (srv *Server) Replace(old *Server) error {
	// Try to start new listeners
	for addr, ln := range srv.Listeners {
		if _, ok := old.Listeners[addr]; ok {
			continue
		}
		if err := ln.Start(); err != nil {
			for _, ln2 := range srv.Listeners {
				ln2.Stop()
			}
			return fmt.Errorf("failed to start listener: %v", err)
		}
	}

	// Steal the old server's ACME cache
	srv.acmeCache = old.acmeCache

	// Restart ACME
	old.cancelACME()
	if err := srv.startACME(); err != nil {
		for _, ln := range srv.Listeners {
			ln.Stop()
		}
		return fmt.Errorf("failed to start ACME: %v", err)
	}

	// Take over existing listeners and terminate old ones
	for addr, oldLn := range old.Listeners {
		if ln, ok := srv.Listeners[addr]; ok {
			srv.Listeners[addr] = oldLn.UpdateFrom(ln)
		} else {
			if err := oldLn.Stop(); err != nil {
				log.Printf("listener %q: failed to stop: %v", addr, err)
			}
		}
	}

	// Cleanup managed certs which are no longer used
	managed := make(map[string]struct{}, len(srv.ManagedNames))
	for _, name := range srv.ManagedNames {
		managed[name] = struct{}{}
	}
	removeManaged := make([]string, 0, len(old.ManagedNames))
	for _, name := range old.ManagedNames {
		if _, ok := managed[name]; !ok {
			removeManaged = append(removeManaged, name)
		}
	}
	srv.acmeCache.cache.RemoveManaged(removeManaged)

	// Cleanup unmanaged certs which are no longer used
	unmanaged := make(map[string]struct{}, len(srv.unmanagedHashes))
	for _, hash := range srv.unmanagedHashes {
		unmanaged[hash] = struct{}{}
	}
	removeUnmanaged := make([]string, 0, len(old.unmanagedHashes))
	for _, hash := range old.unmanagedHashes {
		if _, ok := unmanaged[hash]; !ok {
			removeUnmanaged = append(removeUnmanaged, hash)
		}
	}
	srv.acmeCache.cache.Remove(removeUnmanaged)

	return nil
}

type clientError struct {
	error
}

type frontendKey struct {
	server   string
	protocol string
}

type listenerHandles struct {
	Server    *Server
	Frontends map[frontendKey]*Frontend
}

type Listener struct {
	Address string
	netLn   net.Listener
	atomic  atomic.Value
}

func newListener(srv *Server, addr string) *Listener {
	ln := &Listener{
		Address: addr,
	}
	ln.atomic.Store(&listenerHandles{
		Server:    srv,
		Frontends: make(map[frontendKey]*Frontend),
	})
	return ln
}

func (ln *Listener) RegisterFrontend(name string, fe *Frontend) error {
	fes := ln.atomic.Load().(*listenerHandles).Frontends
	for _, proto := range fe.Protocols {
		key := frontendKey{
			server:   name,
			protocol: proto,
		}
		if _, ok := fes[key]; ok {
			return fmt.Errorf("listener %q: duplicate frontends for server name %q and protocol %q", ln.Address, name, proto)
		}
		fes[key] = fe
	}
	noProto := frontendKey{
		server: name,
	}
	if _, ok := fes[noProto]; !ok {
		fes[noProto] = fe
	}
	return nil
}

func (ln *Listener) Start() error {
	var err error
	ln.netLn, err = net.Listen("tcp", ln.Address)
	if err != nil {
		return err
	}
	log.Printf("listening on %q", ln.Address)

	ln.netLn = &retryListener{Listener: ln.netLn}

	go func() {
		if err := ln.serve(); err != nil {
			log.Fatalf("listener %q: %v", ln.Address, err)
		}
	}()

	return nil
}

func (ln *Listener) Stop() error {
	return ln.netLn.Close()
}

func (ln *Listener) UpdateFrom(new *Listener) *Listener {
	ln.atomic.Store(new.atomic.Load())
	return ln
}

func (ln *Listener) serve() error {
	for {
		conn, err := ln.netLn.Accept()
		if errors.Is(err, net.ErrClosed) {
			// Listening socket has been closed by Stop()
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to accept connection: %v", err)
		}

		go func() {
			err := ln.handle(conn)
			if err == nil {
				return
			}
			srv := ln.atomic.Load().(*listenerHandles).Server
			var clientErr clientError
			if !errors.As(err, &clientErr) || srv.Debug {
				log.Printf("listener %q: connection %q: %v", ln.Address, conn.RemoteAddr(), err)
			}
		}()
	}
}

func (ln *Listener) handle(conn net.Conn) error {
	defer conn.Close()
	srv := ln.atomic.Load().(*listenerHandles).Server

	tlsConfig := srv.ACMEConfig.TLSConfig()
	getConfigForClient := tlsConfig.GetConfigForClient
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Call previous GetConfigForClient function, if any
		var tlsConfig *tls.Config
		if getConfigForClient != nil {
			var err error
			tlsConfig, err = getConfigForClient(hello)
			if err != nil {
				return nil, err
			}
		} else {
			tlsConfig = srv.ACMEConfig.TLSConfig()
		}

		fes := ln.atomic.Load().(*listenerHandles).Frontends
		serverName := hello.ServerName
		ok := false
		for key, fe := range fes {
			if key.server == serverName {
				ok = true
				if key.protocol != "" {
					tlsConfig.NextProtos = append(tlsConfig.NextProtos, key.protocol)
					if fe.ClientAuth != tls.NoClientCert {
						tlsConfig.ClientAuth = fe.ClientAuth
						tlsConfig.ClientCAs = fe.ClientCAs
					}
				}
			}
		}
		if ok {
			return tlsConfig, nil
		}
		serverName = wildcard(serverName)
		if serverName != "" {
			for key, fe := range fes {
				if key.server == serverName {
					ok = true
					if key.protocol != "" {
						tlsConfig.NextProtos = append(tlsConfig.NextProtos, key.protocol)
						if fe.ClientAuth != tls.NoClientCert {
							tlsConfig.ClientAuth = fe.ClientAuth
							tlsConfig.ClientCAs = fe.ClientCAs
						}
					}
				}
			}
		}
		if ok {
			return tlsConfig, nil
		}
		return nil, fmt.Errorf("can't find frontend for server name %q", serverName)
	}
	tlsConn := tls.Server(conn, tlsConfig)

	if err := tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return fmt.Errorf("failed to set TLS handshake timeout: %v", err)
	}
	if err := tlsConn.Handshake(); err == io.EOF {
		return nil
	} else if err != nil {
		return clientError{fmt.Errorf("TLS handshake failed: %v", err)}
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to reset TLS handshake timeout: %v", err)
	}
	// TODO: allow setting custom downstream timeouts

	tlsState := tlsConn.ConnectionState()
	fe, err := ln.matchFrontend(tlsState.ServerName, tlsState.NegotiatedProtocol)
	if err != nil {
		return err
	}

	return fe.handle(tlsConn, &tlsState)
}

func wildcard(name string) string {
	// Match wildcard certificates, allowing only a single, non-partial
	// wildcard, in the left-most label
	i := strings.IndexByte(name, '.')
	// Don't allow wildcards with only a TLD (e.g. *.com)
	if i >= 0 && strings.IndexByte(name[i+1:], '.') >= 0 {
		return "*" + name[i:]
	}
	return ""
}

func (ln *Listener) matchFrontend(serverName string, protocol string) (*Frontend, error) {
	fes := ln.atomic.Load().(*listenerHandles).Frontends
	fe, ok := fes[frontendKey{
		server:   serverName,
		protocol: protocol,
	}]
	if !ok {
		fe, ok = fes[frontendKey{
			server:   wildcard(serverName),
			protocol: protocol,
		}]
	}
	if !ok {
		fe, ok = fes[frontendKey{
			server:   "",
			protocol: protocol,
		}]
	}
	if !ok {
		return nil, fmt.Errorf("can't find frontend for server name %q and protocol %q", serverName, protocol)
	}
	return fe, nil
}

type Frontend struct {
	Backend    Backend
	Protocols  []string
	ClientAuth tls.ClientAuthType
	ClientCAs  *x509.CertPool
}

func (fe *Frontend) handle(downstream net.Conn, tlsState *tls.ConnectionState) error {
	defer downstream.Close()

	// TODO: setup upstream timeouts

	be := &fe.Backend
	upstream, err := net.Dial(be.Network, be.Address)
	if err != nil {
		return fmt.Errorf("failed to dial backend: %v", err)
	}
	if be.TLSConfig != nil {
		upstream = tls.Client(upstream, be.TLSConfig)
	}
	defer upstream.Close()

	if be.Proxy {
		h := proxyproto.HeaderProxyFromAddrs(byte(be.ProxyVersion), downstream.RemoteAddr(), downstream.LocalAddr())

		var tlvs []proxyproto.TLV
		if tlsState.ServerName != "" {
			tlvs = append(tlvs, authorityTLV(tlsState.ServerName))
		}
		if tlsState.NegotiatedProtocol != "" {
			tlvs = append(tlvs, alpnTLV(tlsState.NegotiatedProtocol))
		}
		if tlv, err := sslTLV(tlsState); err != nil {
			return fmt.Errorf("failed to set PROXY protocol header SSL TLV: %v", err)
		} else {
			tlvs = append(tlvs, tlv)
		}
		if err := h.SetTLVs(tlvs); err != nil {
			return fmt.Errorf("failed to set PROXY protocol header TLVs: %v", err)
		}

		if _, err := h.WriteTo(upstream); err != nil {
			return fmt.Errorf("failed to write PROXY protocol header: %v", err)
		}
	}

	if err := duplexCopy(upstream, downstream); err != nil {
		return clientError{fmt.Errorf("failed to copy bytes: %v", err)}
	}
	return nil
}

type Backend struct {
	Network      string
	Address      string
	Proxy        bool
	ProxyVersion int
	TLSConfig    *tls.Config // nil if no TLS
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
		Type:  proxyproto.PP2_TYPE_AUTHORITY,
		Value: []byte(name),
	}
}

func alpnTLV(proto string) proxyproto.TLV {
	return proxyproto.TLV{
		Type:  proxyproto.PP2_TYPE_ALPN,
		Value: []byte(proto),
	}
}

func sslTLV(state *tls.ConnectionState) (proxyproto.TLV, error) {
	pp2ssl := tlvparse.PP2SSL{
		Client: tlvparse.PP2_BITFIELD_CLIENT_SSL, // all of our connections are TLS
		Verify: 1,                                // we haven't checked the client cert
	}

	var version string
	switch state.Version {
	case tls.VersionTLS10:
		version = "TLSv1.0"
	case tls.VersionTLS11:
		version = "TLSv1.1"
	case tls.VersionTLS12:
		version = "TLSv1.2"
	case tls.VersionTLS13:
		version = "TLSv1.3"
	}
	if version != "" {
		versionTLV := proxyproto.TLV{
			Type:  proxyproto.PP2_SUBTYPE_SSL_VERSION,
			Value: []byte(version),
		}
		pp2ssl.TLV = append(pp2ssl.TLV, versionTLV)
	}

	// TODO: add PP2_SUBTYPE_SSL_CIPHER, PP2_SUBTYPE_SSL_SIG_ALG, PP2_SUBTYPE_SSL_KEY_ALG
	// TODO: check client-provided cert, if any

	return pp2ssl.Marshal()
}

type retryListener struct {
	net.Listener

	delay time.Duration
}

func (ln *retryListener) Accept() (net.Conn, error) {
	for {
		conn, err := ln.Listener.Accept()
		if ne, ok := err.(net.Error); ok && ne.Temporary() {
			if ln.delay == 0 {
				ln.delay = 5 * time.Millisecond
			} else {
				ln.delay *= 2
			}
			if max := 1 * time.Second; ln.delay > max {
				ln.delay = max
			}
			log.Printf("listener %q: accept error (retrying in %v): %v", ln.Addr(), ln.delay, err)
			time.Sleep(ln.delay)
		} else {
			ln.delay = 0
			return conn, err
		}
	}
}
