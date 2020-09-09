# tlstunnel

A TLS reverse proxy.

- Automatic TLS with Let's Encrypt
- Route incoming connections to backends using Server Name Indication
- Support for the [PROXY protocol]

Example configuration:

    frontend example.org:443 {
        backend localhost:8080
    }

See the man page for more information.

## License

MIT

[PROXY protocol]: https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt
