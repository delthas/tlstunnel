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

tlstunnel will reload the config file when it receives the HUP signal.

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
		- _tls://<host>:<port>_ connects to a TLS over TCP server
		- _unix://<path>_ connects to a Unix socket

		The _+proxy_ suffix can be added to the URI scheme to forward
		connection metadata via the PROXY protocol.

	*tls* { ... }
		Customise frontend-specific TLS configuration.

		The tls directive supports the following sub-directives:

		*load* <cert> <key>
			Load certificates and private keys from PEM files.

			This disables automatic TLS.

	*protocol* <name>...
		List of supported application-layer protocols.

		The first protocol which is also supported by the client is negociated.

		The protocols will be advertised via the TLS ALPN extension. See the
		IANA registry for a list of protocol names:
		https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids

		For instance, for an HTTP server supporting HTTP/1 and HTTP/2:

		```
		protocol h2 http/1.1 http/1.0
		```

*tls* { ... }
	Customise global TLS configuration.

	The tls directive supports the following sub-directives:

	*acme_ca* <url>
		ACME Certificate Authority endpoint.

	*email* <address>
		The email address to use when creating or selecting an existing ACME
		server account

	*on_demand* { ... }
		Enable on-demand TLS.

		When enabled, a TLS handshake may trigger maintenance for the relevant
		certificate. If no existing certificate is available, a new certificate
		is obtained and the connection is blocked until it's available. If an
		existing certificate is available, the certificate is renewed in the
		background if necessary.

		Warning: to prevent abuse, you should specify a _validate_command_
		sub-directive.

		The on_demand directive supports the following optional sub-directives:

		*validate_command* command [arguments...]
			Command to run before an on-demand certificate is obtained. If the
			command returns a non-zero exit status, the request is denied.

			The environment will contain a *TLSTUNNEL_NAME* variable with the
			domain name to be validated.

# FILES

_/etc/tlstunnel/config_
	Default configuration file location.

_/var/lib/tlstunnel_
	State files such as certificates are stored in this directory.

# AUTHORS

Maintained by Simon Ser <contact@emersion.fr>, who is assisted by other
open-source contributors. For more information about tlstunnel development, see
<https://git.sr.ht/~emersion/tlstunnel>.
