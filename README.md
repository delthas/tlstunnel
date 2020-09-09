# tlstunnel

A TLS reverse proxy.

- Automatic TLS with Let's Encrypt
- Route incoming connections to backends using Server Name Indication

Example configuration:

    frontend example.org:443 {
        backend localhost:8080
    }

## License

MIT
