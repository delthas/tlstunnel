# [tlstunnel]

[![builds.sr.ht status](https://builds.sr.ht/~emersion/tlstunnel/commits/master.svg)](https://builds.sr.ht/~emersion/tlstunnel/commits/master?)

A TLS reverse proxy.

- Automatic TLS with Let's Encrypt
- Route incoming connections to backends using Server Name Indication
- Support for the [PROXY protocol]

Example configuration:

    frontend example.org:443 {
        backend localhost:8080
    }

See the man page for more information.

## Contributing

Send patches to the [mailing list], report bugs on the [issue tracker].
Discuss in [#emersion on Libera Chat].

## License

MIT

[tlstunnel]: https://sr.ht/~emersion/tlstunnel/
[PROXY protocol]: https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt
[mailing list]: https://lists.sr.ht/~emersion/public-inbox
[issue tracker]: https://todo.sr.ht/~emersion/tlstunnel
[#emersion on Libera Chat]: ircs://irc.libera.chat/#emersion
