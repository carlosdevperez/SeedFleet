// Package fleet provides device discovery and inventory operations.
package fleet

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
	"github.com/carlosdevperez/seedfleet/pkg/fleet/internal/dockerinstaller"
	"github.com/carlosdevperez/seedfleet/pkg/fleet/internal/inventory"
	internalscanner "github.com/carlosdevperez/seedfleet/pkg/fleet/internal/scanner"
)

var (
	// ErrScanInProgress is returned when a scan is already running.
	ErrScanInProgress = errors.New("a scan is already running")
	// ErrDeploymentInProgress is returned when another deployment is running.
	ErrDeploymentInProgress = errors.New("a deployment is already running")
)

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

// DockerInstallTarget identifies a host reachable through the local SSH
// client. An empty user or zero port defers to the caller's SSH configuration.
type DockerInstallTarget struct {
	Host string
	User string
	Port uint16
}

// DockerInstallStatus reports whether a deployment changed its target.
type DockerInstallStatus string

const (
	DockerInstalled      DockerInstallStatus = "installed"
	DockerAlreadyPresent DockerInstallStatus = "already-installed"
)

// DockerInstallResult describes a successful Docker installation.
type DockerInstallResult struct {
	Target  DockerInstallTarget
	Status  DockerInstallStatus
	Version string
}

// InvalidDeploymentTargetError reports an SSH target that is missing or
// contains characters that cannot safely be passed to SSH.
type InvalidDeploymentTargetError struct {
	Reason string
}

func (e *InvalidDeploymentTargetError) Error() string {
	return e.Reason
}

type scanner interface {
	Scan(context.Context, string) (internalscanner.Result, error)
}

type deviceInventory interface {
	Save(context.Context, []devices.Device) ([]devices.Device, error)
	List(context.Context) ([]devices.Device, error)
}

type dockerInstaller interface {
	Install(context.Context, string, string, uint16) (dockerinstaller.Result, error)
}

// Provider performs fleet discovery and retains the current device inventory.
type Provider struct {
	scanner         scanner
	inventory       deviceInventory
	dockerInstaller dockerInstaller
	running         atomic.Bool
	deployingDocker atomic.Bool
}

// NewProvider returns a Provider configured with options.
func NewProvider(options ...ProviderOption) (*Provider, error) {
	opts := providerOptions{scannerConfig: internalscanner.DefaultConfig()}
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
	return &Provider{
		scanner:         internalscanner.New(opts.scannerConfig),
		inventory:       inventory.New(),
		dockerInstaller: dockerinstaller.New(),
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

// InstallDocker installs Docker Engine on a Linux host over SSH. The operation
// is synchronous and only one Docker deployment may run at a time.
func (p *Provider) InstallDocker(ctx context.Context, target DockerInstallTarget) (DockerInstallResult, error) {
	if !p.deployingDocker.CompareAndSwap(false, true) {
		return DockerInstallResult{}, ErrDeploymentInProgress
	}
	defer p.deployingDocker.Store(false)

	result, err := p.dockerInstaller.Install(ctx, target.Host, target.User, target.Port)
	if err != nil {
		var invalid *dockerinstaller.InvalidTargetError
		if errors.As(err, &invalid) {
			return DockerInstallResult{}, &InvalidDeploymentTargetError{Reason: invalid.Reason}
		}
		return DockerInstallResult{}, err
	}
	return DockerInstallResult{
		Target:  target,
		Status:  DockerInstallStatus(result.Status),
		Version: result.Version,
	}, nil
}
