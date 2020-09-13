# DNS challenge

DNS challenges are disabled by default. To enable them, you need to:
- enable build-time support for DNS challenges
- enable DNS challenges in your tlstunnel configuration

## Enabling support for DNS challenges

To enable build-time support for DNS challenges, build tlstunnel with the `dns` Go build tag:

```
go build -tags dns
```

## Using DNS challenges in the tlstunnel configuration

To use DNS challenges after you've added support for them, add a `tls` block with a `dns` directive in your configuration.

The format of the `dns` directive is: `dns <provider_name> [<parameter>...]`, with each DNS provider having its own specific list of parameters. See the next section for details.

For example, to enable DNS challenges for Gandi, add to your configuration file:
```
tls {
    dns gandi "my-gandi-api-key"
}
```

## DNS providers & configuration parameters

| Provider | Parameter 1 | Parameter 2 |
| --- | --- | --- |
| digitalocean | [Personal access token](https://github.com/digitalocean/godo#authentication) | |
