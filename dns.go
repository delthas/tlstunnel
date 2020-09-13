package tlstunnel

import "github.com/caddyserver/certmagic"

type Provider func(params ...string) (provider certmagic.ACMEDNSProvider, err error)

var Providers = make(map[string]Provider)

func RegisterDNS(name string, provider Provider) {
	Providers[name] = provider
}
