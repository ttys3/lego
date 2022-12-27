package azure

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-acme/lego/v4/providers/dns/azure/to"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
)

// dnsProvider implements the challenge.Provider interface for Azure DNS.
type dnsProvider struct {
	config     *Config
	authorizer *azidentity.EnvironmentCredential
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *dnsProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *dnsProvider) Present(domain, token, keyAuth string) error {
	ctx := context.Background()
	fqdn, value := dns01.GetRecord(domain, keyAuth)

	zone, err := d.getHostedZoneID(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}

	rsc, err := armdns.NewRecordSetsClient(d.config.SubscriptionID, d.authorizer, nil)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}

	subDomain, err := dns01.ExtractSubDomain(fqdn, zone)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}

	// Get existing record set
	rset, err := rsc.Get(ctx, d.config.ResourceGroup, zone, subDomain, armdns.RecordTypeTXT, nil)
	if err != nil {
		var detailed = &azcore.ResponseError{}
		if !errors.As(err, &detailed) || detailed.StatusCode != http.StatusNotFound {
			return fmt.Errorf("azure: %w", err)
		}
	}

	// Construct unique TXT records using map
	uniqRecords := map[string]struct{}{value: {}}
	if rset.Properties != nil && rset.Properties.TxtRecords != nil {
		for _, txtRecord := range rset.Properties.TxtRecords {
			// Assume Value doesn't contain multiple strings
			if len(txtRecord.Value) > 0 && txtRecord.Value[0] != nil {
				uniqRecords[*txtRecord.Value[0]] = struct{}{}
			}
		}
	}

	var txtRecords []*armdns.TxtRecord
	for txt := range uniqRecords {
		txtRecords = append(txtRecords, &armdns.TxtRecord{Value: []*string{&txt}})
	}

	rec := armdns.RecordSet{
		Name: &subDomain,
		Properties: &armdns.RecordSetProperties{
			TTL:        to.Int64Ptr(int64(d.config.TTL)),
			TxtRecords: txtRecords,
		},
	}

	_, err = rsc.CreateOrUpdate(ctx, d.config.ResourceGroup, zone, subDomain, armdns.RecordTypeTXT, rec, nil)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *dnsProvider) CleanUp(domain, token, keyAuth string) error {
	ctx := context.Background()
	fqdn, _ := dns01.GetRecord(domain, keyAuth)

	zone, err := d.getHostedZoneID(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}

	subDomain, err := dns01.ExtractSubDomain(fqdn, zone)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}

	rsc, err := armdns.NewRecordSetsClient(d.config.SubscriptionID, d.authorizer, nil)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}

	_, err = rsc.Delete(ctx, d.config.ResourceGroup, zone, subDomain, armdns.RecordTypeTXT, nil)
	if err != nil {
		return fmt.Errorf("azure: %w", err)
	}
	return nil
}

// Checks that azure has a zone for this domain name.
func (d *dnsProvider) getHostedZoneID(ctx context.Context, fqdn string) (string, error) {
	if zone := env.GetOrFile(EnvZoneName); zone != "" {
		return zone, nil
	}

	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return "", err
	}

	dc, err := armdns.NewZonesClient(d.config.SubscriptionID, d.authorizer, nil)
	if err != nil {
		return "", err
	}

	zone, err := dc.Get(ctx, d.config.ResourceGroup, dns01.UnFqdn(authZone), nil)
	if err != nil {
		return "", err
	}

	// zone.Name shouldn't have a trailing dot(.)
	return to.String(zone.Name), nil
}
