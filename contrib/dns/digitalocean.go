package dns

import (
	"git.sr.ht/~emersion/tlstunnel"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/digitalocean"
)

func init() {
	tlstunnel.RegisterDNS("digitalocean", func(params ...string) (provider certmagic.ACMEDNSProvider, err error) {
		var token string
		if err := getParams(params, &token); err != nil {
			return nil, err
		}
		return &digitalocean.Provider{
			APIToken: token,
		}, nil
	})
}
