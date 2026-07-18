package fleet

import (
	"fmt"
	"net/netip"

	internalscanner "github.com/carlosdevperez/seedfleet/pkg/fleet/internal/scanner"
)

type providerOptions struct {
	scannerConfig internalscanner.Config
}

// ProviderOption configures a Provider.
type ProviderOption interface {
	apply(*providerOptions) error
}

type providerOption func(*providerOptions) error

func (option providerOption) apply(opts *providerOptions) error {
	return option(opts)
}

var _ ProviderOption = providerOption(nil)

// ProviderWithAliasFile loads stable device names from path. A missing file is
// treated as an empty alias set.
func ProviderWithAliasFile(path string) ProviderOption {
	return providerOption(func(opts *providerOptions) error {
		aliases, err := internalscanner.LoadAliases(path)
		if err != nil {
			return fmt.Errorf("failed to load device aliases: %w", err)
		}
		opts.scannerConfig.Aliases = aliases
		return nil
	})
}

// ProviderWithAllowedNetworks restricts scans to the supplied IPv4 CIDRs.
func ProviderWithAllowedNetworks(networks ...netip.Prefix) ProviderOption {
	return providerOption(func(opts *providerOptions) error {
		allowed := make([]netip.Prefix, len(networks))
		for index, network := range networks {
			if !network.IsValid() || !network.Addr().Is4() {
				return fmt.Errorf("allowed network must be an IPv4 CIDR: %q", network)
			}
			allowed[index] = network.Masked()
		}
		opts.scannerConfig.AllowedNetworks = allowed
		return nil
	})
}

// ProviderWithRoutedNetworks allows explicitly allowlisted routed networks.
func ProviderWithRoutedNetworks() ProviderOption {
	return providerOption(func(opts *providerOptions) error {
		opts.scannerConfig.AllowRoutedNetworks = true
		return nil
	})
}
