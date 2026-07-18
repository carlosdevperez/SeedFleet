// Package fleet provides device discovery and inventory operations.
package fleet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

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
	InspectTCP(context.Context, netip.Addr, internalscanner.TCPProfile) (internalscanner.TCPInspection, error)
}

type deviceInventory interface {
	Save(context.Context, []devices.Device) ([]devices.Device, error)
	Get(context.Context, devices.ID) (devices.Device, bool, error)
	List(context.Context) ([]devices.Device, error)
	Close() error
}

var (
	_ deviceInventory = (*inventory.Memory)(nil)
	_ deviceInventory = (*inventory.SQLite)(nil)
)

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

	inspectionMu    sync.Mutex
	inspectionCache map[portInspectionKey]cachedPortInspection
	inspectionCalls map[portInspectionKey]*portInspectionCall
	inspectionTTL   time.Duration
	inspectionNow   func() time.Time
}

const defaultPortInspectionCacheTTL = 5 * time.Minute

type portInspectionKey struct {
	deviceID devices.ID
	ip       netip.Addr
	profile  PortInspectionProfile
}

type cachedPortInspection struct {
	result    PortInspectionResult
	expiresAt time.Time
}

type portInspectionCall struct {
	done   chan struct{}
	result PortInspectionResult
	err    error
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
		scanner:         internalscanner.New(opts.scannerConfig),
		inventory:       deviceStore,
		dockerInstaller: dockerinstaller.New(),
		inspectionCache: make(map[portInspectionKey]cachedPortInspection),
		inspectionCalls: make(map[portInspectionKey]*portInspectionCall),
		inspectionTTL:   defaultPortInspectionCacheTTL,
		inspectionNow:   time.Now,
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

// InspectPorts performs an explicit TCP inspection against one inventoried
// device. Completed results are cached briefly and identical concurrent calls
// share the same network work.
func (p *Provider) InspectPorts(ctx context.Context, request PortInspectionRequest) (PortInspectionResult, error) {
	profile, scannerProfile, err := normalizePortInspectionProfile(request.Profile)
	if err != nil {
		return PortInspectionResult{}, err
	}
	if request.DeviceID == "" {
		return PortInspectionResult{}, &InvalidPortInspectionError{Reason: "device ID is required"}
	}
	device, ok, err := p.inventory.Get(ctx, request.DeviceID)
	if err != nil {
		return PortInspectionResult{}, err
	}
	if !ok {
		return PortInspectionResult{}, fmt.Errorf("%w: %s", ErrDeviceNotFound, request.DeviceID)
	}

	key := portInspectionKey{deviceID: device.ID, ip: device.IP, profile: profile}
	now := p.portInspectionNow()
	p.inspectionMu.Lock()
	p.initializePortInspectionStateLocked()
	if cached, ok := p.inspectionCache[key]; !request.Refresh && ok && now.Before(cached.expiresAt) {
		result := clonePortInspection(cached.result)
		result.Cached = true
		p.inspectionMu.Unlock()
		return result, nil
	}
	if call, ok := p.inspectionCalls[key]; ok {
		p.inspectionMu.Unlock()
		select {
		case <-call.done:
			result := clonePortInspection(call.result)
			result.Cached = call.err == nil
			return result, call.err
		case <-ctx.Done():
			return PortInspectionResult{}, ctx.Err()
		}
	}
	call := &portInspectionCall{done: make(chan struct{})}
	p.inspectionCalls[key] = call
	p.inspectionMu.Unlock()

	inspected, inspectErr := p.scanner.InspectTCP(ctx, device.IP, scannerProfile)
	result := PortInspectionResult{}
	if inspectErr == nil {
		result = PortInspectionResult{
			DeviceID:        device.ID,
			IP:              device.IP,
			Profile:         profile,
			OpenPorts:       append([]uint16(nil), inspected.OpenPorts...),
			Reachable:       inspected.Reachable,
			PortsProbed:     inspected.PortsProbed,
			PeakConcurrency: inspected.PeakConcurrency,
			InspectedAt:     p.portInspectionNow().UTC(),
			Duration:        inspected.Duration,
		}
	}

	p.inspectionMu.Lock()
	call.result = clonePortInspection(result)
	call.err = inspectErr
	if inspectErr == nil {
		p.inspectionCache[key] = cachedPortInspection{
			result:    clonePortInspection(result),
			expiresAt: result.InspectedAt.Add(p.inspectionTTL),
		}
	}
	delete(p.inspectionCalls, key)
	close(call.done)
	p.inspectionMu.Unlock()
	return result, inspectErr
}

func normalizePortInspectionProfile(profile PortInspectionProfile) (PortInspectionProfile, internalscanner.TCPProfile, error) {
	if profile == "" {
		profile = PortInspectionServices
	}
	switch profile {
	case PortInspectionServices:
		return profile, internalscanner.TCPProfileServices, nil
	case PortInspectionCommon:
		return profile, internalscanner.TCPProfileCommon, nil
	case PortInspectionFullTCP:
		return profile, internalscanner.TCPProfileFull, nil
	default:
		return "", "", &InvalidPortInspectionError{Reason: fmt.Sprintf("unknown port inspection profile %q", profile)}
	}
}

func (p *Provider) initializePortInspectionStateLocked() {
	if p.inspectionCache == nil {
		p.inspectionCache = make(map[portInspectionKey]cachedPortInspection)
	}
	if p.inspectionCalls == nil {
		p.inspectionCalls = make(map[portInspectionKey]*portInspectionCall)
	}
	if p.inspectionTTL <= 0 {
		p.inspectionTTL = defaultPortInspectionCacheTTL
	}
}

func (p *Provider) portInspectionNow() time.Time {
	if p.inspectionNow != nil {
		return p.inspectionNow()
	}
	return time.Now()
}

func clonePortInspection(result PortInspectionResult) PortInspectionResult {
	result.OpenPorts = append([]uint16(nil), result.OpenPorts...)
	return result
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

// Close releases resources held by the configured inventory.
func (p *Provider) Close() error {
	if p == nil || p.inventory == nil {
		return nil
	}
	return p.inventory.Close()
}
