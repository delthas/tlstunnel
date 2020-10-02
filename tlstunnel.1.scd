tlstunnel(1)

# NAME

tlstunnel - TLS reverse proxy

# SYNOPSIS

*tlstunnel* [options...]

# DESCRIPTION

tlstunnel is a TLS reverse proxy with support for automatic TLS certificate
retrieval via the ACME protocol.

# OPTIONS

*-h*, *-help*
	Show help message and quit.

*-config* <path>
	Path to the configuration file.

# CONFIG FILE

The config file has one directive per line. Directives have a name, followed
by parameters separated by space characters. Directives may have children in
blocks delimited by "{" and "}". Lines beginning with "#" are comments.

Example:

```
frontend example.org:443 {
    backend localhost:8080
}
```

The following directives are supported:

*frontend* <address>... { ... }
	Addresses to listen on for incoming TLS connections.

	Each address is in the form _<name>:<port>_. The name may be omitted.

	The frontend directive supports the following sub-directives:

	*backend* <uri>...
		Backend to forward incoming connections to.

		The following URIs are supported:

		- _[tcp://]<host>:<port>_ connects to a TCP server
		- _unix://<path>_ connects to a Unix socket

		The _+proxy_ suffix can be added to the URI scheme to forward
		connection metadata via the PROXY protocol.


*tls* { ... }
	Customise TLS configuration.

	The tls directive supports the following sub-directives:

	*acme_ca* <url>
		ACME Certificate Authority endpoint.

	*email* <address>
		The email address to use when creating or selecting an existing ACME
		server account

# FILES

_/etc/tlstunnel/config_
	Default configuration file location.

_/var/lib/tlstunnel_
	State files such as certificates are stored in this directory.

# AUTHORS

Maintained by Simon Ser <contact@emersion.fr>, who is assisted by other
open-source contributors. For more information about tlstunnel development, see
https://git.sr.ht/~emersion/tlstunnel.
