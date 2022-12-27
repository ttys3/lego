// Package azure implements a DNS provider for solving the DNS-01 challenge using azure DNS.
// Azure doesn't like trailing dots on domain names, most of the acme code does.
package azure

import (
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/platform/config/env"
)

const defaultMetadataEndpoint = "http://169.254.169.254"

// Environment variables names.
const (
	envNamespace = "AZURE_"

	EnvEnvironment = envNamespace + "ENVIRONMENT"

	EnvSubscriptionID = envNamespace + "SUBSCRIPTION_ID"
	EnvResourceGroup  = envNamespace + "RESOURCE_GROUP"
	EnvTenantID       = envNamespace + "TENANT_ID"
	EnvClientID       = envNamespace + "CLIENT_ID"
	EnvClientSecret   = envNamespace + "CLIENT_SECRET"

	EnvZoneName    = envNamespace + "ZONE_NAME"
	EnvPrivateZone = envNamespace + "PRIVATE_ZONE"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	// optional if using instance metadata service
	ClientID     string
	ClientSecret string
	TenantID     string

	SubscriptionID string
	ResourceGroup  string
	PrivateZone    bool

	MetadataEndpoint string

	CloudConfig cloud.Configuration

	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
	HTTPClient         *http.Client
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, 60),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 2*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 2*time.Second),
		CloudConfig:        cloud.AzurePublic,
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	provider challenge.ProviderTimeout
}

// NewDNSProvider returns a DNSProvider instance configured for azure.
// Credentials can be passed in the environment variables:
// AZURE_ENVIRONMENT, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
// AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_RESOURCE_GROUP
// If the credentials are _not_ set via the environment,
// then it will attempt to get a bearer token via the instance metadata service.
// see: https://github.com/Azure/go-autorest/blob/v10.14.0/autorest/azure/auth/auth.go#L38-L42
func NewDNSProvider() (*DNSProvider, error) {
	config := NewDefaultConfig()

	environmentName := env.GetOrFile(EnvEnvironment)
	if environmentName != "" {
		var environment cloud.Configuration
		switch environmentName {
		case "china":
			environment = cloud.AzureChina
		case "german":
			// see https://learn.microsoft.com/en-us/previous-versions/azure/germany/germany-developer-guide#endpoint-mapping
			environment = cloud.Configuration{
				ActiveDirectoryAuthorityHost: "https://login.microsoftonline.de/", Services: map[cloud.ServiceName]cloud.ServiceConfiguration{},
			}
		case "public":
			environment = cloud.AzurePublic
		case "usgovernment":
			environment = cloud.AzureGovernment
		default:
			return nil, fmt.Errorf("azure: unknown environment %s", environmentName)
		}

		config.CloudConfig = environment
	}

	config.SubscriptionID = env.GetOrFile(EnvSubscriptionID)
	config.ResourceGroup = env.GetOrFile(EnvResourceGroup)
	config.ClientSecret = env.GetOrFile(EnvClientSecret)
	config.ClientID = env.GetOrFile(EnvClientID)
	config.TenantID = env.GetOrFile(EnvTenantID)
	config.PrivateZone = env.GetOrDefaultBool(EnvPrivateZone, false)

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for Azure.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("azure: the configuration of the DNS provider is nil")
	}

	if config.HTTPClient == nil {
		config.HTTPClient = http.DefaultClient
	}

	if config.SubscriptionID == "" {
		return nil, errors.New("azure: SubscriptionID is missing")
	}

	if config.ResourceGroup == "" {
		return nil, errors.New("azure: ResourceGroup is missing")
	}

	clientOpts := azcore.ClientOptions{Cloud: cloud.AzureChina}
	cred, err := azidentity.NewEnvironmentCredential(&azidentity.EnvironmentCredentialOptions{ClientOptions: clientOpts})
	// cred, err := azidentity.NewClientSecretCredential(
	// 	config.TenantID, config.ClientID, config.ClientSecret, &azidentity.ClientSecretCredentialOptions{ClientOptions: clientOpts},
	// )

	if err != nil {
		return nil, fmt.Errorf("azidentity.NewEnvironmentCredential failed: %w", err)
	}

	return &DNSProvider{provider: &dnsProvider{config: config, authorizer: cred}}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.provider.Timeout()
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	return d.provider.Present(domain, token, keyAuth)
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	return d.provider.CleanUp(domain, token, keyAuth)
}
