package main

import (
	"fmt"
	"io"
	"net"
)

type Server struct {
	Frontends []*Frontend
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

		// TODO: log errors to debug log
		go fe.handle(conn)
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
