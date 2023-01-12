package tlstunnel

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
)

type commandDNSProvider struct {
	Name   string
	Params []string
}

var _ certmagic.ACMEDNSProvider = (*commandDNSProvider)(nil)

func (provider *commandDNSProvider) exec(ctx context.Context, subcmd string, subargs ...string) error {
	var params []string
	params = append(params, provider.Params...)
	params = append(params, subcmd)
	params = append(params, subargs...)
	cmd := exec.CommandContext(ctx, provider.Name, params...)

	if out, err := cmd.CombinedOutput(); err != nil {
		details := ""
		if len(out) > 0 {
			details = ": " + string(out)
		}
		return fmt.Errorf("failed to run DNS hook %v (%w)%v", subcmd, err, details)
	}

	return nil
}

func (provider *commandDNSProvider) processRecords(ctx context.Context, zone string, recs []libdns.Record, subcmd string) ([]libdns.Record, error) {
	var (
		done []libdns.Record
		err  error
	)
	for _, rec := range recs {
		var domain string
		if domain, err = domainFromACMEChallengeRecord(zone, &rec); err != nil {
			break
		}
		if err = provider.exec(ctx, subcmd, domain, "-", rec.Value); err != nil {
			break
		}
		done = append(done, rec)
	}
	return done, err
}

func (provider *commandDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return provider.processRecords(ctx, zone, recs, "deploy_challenge")
}

func (provider *commandDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return provider.processRecords(ctx, zone, recs, "clean_challenge")
}

func domainFromACMEChallengeRecord(zone string, rec *libdns.Record) (string, error) {
	if rec.Type != "TXT" || !strings.HasPrefix(rec.Name, "_acme-challenge.") {
		return "", fmt.Errorf("DNS record doesn't look like an ACME challenge: %v %v", rec.Type, rec.Name)
	}
	relName := strings.TrimPrefix(rec.Name, "_acme-challenge.")
	relZone := strings.TrimSuffix(zone, ".")
	return relName + "." + relZone, nil
}
