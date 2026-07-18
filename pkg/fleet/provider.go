// Package fleet provides device discovery and inventory operations.
package fleet

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
	"github.com/carlosdevperez/seedfleet/pkg/fleet/internal/inventory"
	internalscanner "github.com/carlosdevperez/seedfleet/pkg/fleet/internal/scanner"
)

// ErrScanInProgress is returned when a scan is already running.
var ErrScanInProgress = errors.New("a scan is already running")

// InvalidNetworkError reports a network outside the provider's safety policy.
type InvalidNetworkError struct {
	Reason string
}

func (e *InvalidNetworkError) Error() string {
	return e.Reason
}

// ScanResult contains the devices observed by one scan.
type ScanResult struct {
	Network string
	Devices []devices.Device
}

type scanner interface {
	Scan(context.Context, string) (internalscanner.Result, error)
}

type deviceInventory interface {
	Save(context.Context, []devices.Device) ([]devices.Device, error)
	List(context.Context) ([]devices.Device, error)
	Close() error
}

var (
	_ deviceInventory = (*inventory.Memory)(nil)
	_ deviceInventory = (*inventory.SQLite)(nil)
)

// Provider performs fleet discovery and retains the current device inventory.
type Provider struct {
	scanner   scanner
	inventory deviceInventory
	running   atomic.Bool
}

// NewProvider returns a Provider configured with options.
func NewProvider(options ...ProviderOption) (*Provider, error) {
	opts := providerOptions{
		scannerConfig: internalscanner.DefaultConfig(),
		newInventory: func() (deviceInventory, error) {
			return inventory.NewMemory(), nil
		},
	}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option.apply(&opts); err != nil {
			return nil, err
		}
	}
	if opts.scannerConfig.AllowRoutedNetworks && len(opts.scannerConfig.AllowedNetworks) == 0 {
		return nil, errors.New("routed network scans require at least one allowed network")
	}
	deviceStore, err := opts.newInventory()
	if err != nil {
		return nil, err
	}
	return &Provider{
		scanner:   internalscanner.New(opts.scannerConfig),
		inventory: deviceStore,
	}, nil
}

// Scan discovers network and atomically stores its observations.
func (p *Provider) Scan(ctx context.Context, network string) (ScanResult, error) {
	if !p.running.CompareAndSwap(false, true) {
		return ScanResult{}, ErrScanInProgress
	}
	defer p.running.Store(false)

	result, err := p.scanner.Scan(ctx, network)
	if err != nil {
		var invalid *internalscanner.InvalidNetworkError
		if errors.As(err, &invalid) {
			return ScanResult{}, &InvalidNetworkError{Reason: invalid.Reason}
		}
		return ScanResult{}, err
	}
	stored, err := p.inventory.Save(ctx, result.Devices)
	if err != nil {
		return ScanResult{}, err
	}
	return ScanResult{Network: result.Network, Devices: stored}, nil
}

// List returns the current inventory sorted by IP address.
func (p *Provider) List(ctx context.Context) ([]devices.Device, error) {
	return p.inventory.List(ctx)
}

// Close releases resources held by the configured inventory.
func (p *Provider) Close() error {
	if p == nil || p.inventory == nil {
		return nil
	}
	return p.inventory.Close()
}
