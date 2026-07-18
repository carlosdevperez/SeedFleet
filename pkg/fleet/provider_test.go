package fleet

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
	"github.com/carlosdevperez/seedfleet/pkg/fleet/internal/dockerinstaller"
	internalscanner "github.com/carlosdevperez/seedfleet/pkg/fleet/internal/scanner"
)

type fakeScanner struct {
	result               internalscanner.Result
	err                  error
	started              chan struct{}
	release              chan struct{}
	inspection           internalscanner.TCPInspection
	inspectionErr        error
	inspectionStarted    chan struct{}
	inspectionRelease    chan struct{}
	inspectionStartOnce  sync.Once
	inspectionCalls      atomic.Int32
	inspectionAddress    netip.Addr
	inspectionTCPProfile internalscanner.TCPProfile
}

func (s *fakeScanner) Scan(ctx context.Context, _ string) (internalscanner.Result, error) {
	if s.started != nil {
		close(s.started)
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return internalscanner.Result{}, ctx.Err()
		}
	}
	return s.result, s.err
}

func (s *fakeScanner) InspectTCP(ctx context.Context, address netip.Addr, profile internalscanner.TCPProfile) (internalscanner.TCPInspection, error) {
	s.inspectionCalls.Add(1)
	s.inspectionAddress = address
	s.inspectionTCPProfile = profile
	if s.inspectionStarted != nil {
		s.inspectionStartOnce.Do(func() { close(s.inspectionStarted) })
	}
	if s.inspectionRelease != nil {
		select {
		case <-s.inspectionRelease:
		case <-ctx.Done():
			return internalscanner.TCPInspection{}, ctx.Err()
		}
	}
	return s.inspection, s.inspectionErr
}

type fakeInventory struct {
	mu    sync.Mutex
	items []devices.Device
}

type fakeDockerInstaller struct {
	host    string
	user    string
	port    uint16
	result  dockerinstaller.Result
	err     error
	started chan struct{}
	release chan struct{}
}

func (i *fakeDockerInstaller) Install(ctx context.Context, host, user string, port uint16) (dockerinstaller.Result, error) {
	i.host = host
	i.user = user
	i.port = port
	if i.started != nil {
		close(i.started)
	}
	if i.release != nil {
		select {
		case <-i.release:
		case <-ctx.Done():
			return dockerinstaller.Result{}, ctx.Err()
		}
	}
	return i.result, i.err
}

func (i *fakeInventory) Save(_ context.Context, items []devices.Device) ([]devices.Device, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.items = append([]devices.Device(nil), items...)
	return i.items, nil
}

func (i *fakeInventory) List(context.Context) ([]devices.Device, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]devices.Device(nil), i.items...), nil
}

func (i *fakeInventory) Get(_ context.Context, id devices.ID) (devices.Device, bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, item := range i.items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return devices.Device{}, false, nil
}

func (i *fakeInventory) Close() error {
	return nil
}

func TestProviderScansAndStoresDevices(t *testing.T) {
	want := devices.Device{IP: netip.MustParseAddr("192.0.2.1"), Name: "router"}
	p := &Provider{
		scanner: &fakeScanner{result: internalscanner.Result{
			Network: "192.0.2.0/24",
			Devices: []devices.Device{want},
		}},
		inventory: &fakeInventory{},
	}

	result, err := p.Scan(context.Background(), "192.0.2.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if result.Network != "192.0.2.0/24" || len(result.Devices) != 1 || result.Devices[0].Name != want.Name {
		t.Fatalf("result = %#v", result)
	}
	stored, err := p.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].IP != want.IP {
		t.Fatalf("stored = %#v", stored)
	}
}

func TestProviderAllowsOnlyOneScan(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p := &Provider{scanner: &fakeScanner{started: started, release: release}, inventory: &fakeInventory{}}
	done := make(chan error, 1)
	go func() {
		_, err := p.Scan(context.Background(), "192.0.2.0/24")
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scan did not start")
	}
	if _, err := p.Scan(context.Background(), "192.0.2.0/24"); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("second scan error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProviderMapsInvalidNetworkError(t *testing.T) {
	p := &Provider{
		scanner:   &fakeScanner{err: &internalscanner.InvalidNetworkError{Reason: "not local"}},
		inventory: &fakeInventory{},
	}
	_, err := p.Scan(context.Background(), "198.51.100.0/24")
	var invalid *InvalidNetworkError
	if !errors.As(err, &invalid) || invalid.Reason != "not local" {
		t.Fatalf("error = %T %v", err, err)
	}
}

func TestProviderRejectsRoutedNetworksWithoutAllowlist(t *testing.T) {
	if _, err := NewProvider(ProviderWithRoutedNetworks()); err == nil {
		t.Fatal("NewProvider accepted routed scans without an allowlist")
	}
}

func TestProviderWithSQLiteInventoryPersistsDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seedfleet.db")
	provider, err := NewProvider(ProviderWithSQLiteInventory(path))
	if err != nil {
		t.Fatal(err)
	}
	want := devices.Device{IP: netip.MustParseAddr("192.0.2.10"), MAC: "aa:bb:cc:dd:ee:ff", Name: "printer"}
	provider.scanner = &fakeScanner{result: internalscanner.Result{
		Network: "192.0.2.0/24",
		Devices: []devices.Device{want},
	}}
	result, err := provider.Scan(context.Background(), "192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewProvider(ProviderWithSQLiteInventory(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close provider: %v", err)
		}
	})
	items, err := reopened.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != result.Devices[0].ID || items[0].Name != want.Name {
		t.Fatalf("reopened inventory = %#v", items)
	}
}

func TestProviderRejectsEmptySQLitePath(t *testing.T) {
	if _, err := NewProvider(ProviderWithSQLiteInventory("")); err == nil {
		t.Fatal("NewProvider accepted an empty SQLite path")
	}
}

func TestProviderInspectsInventoriedDevice(t *testing.T) {
	device := devices.Device{ID: "dev_test", IP: netip.MustParseAddr("192.0.2.10")}
	scanner := &fakeScanner{inspection: internalscanner.TCPInspection{
		OpenPorts:       []uint16{22, 443},
		Reachable:       true,
		PortsProbed:     23,
		PeakConcurrency: 16,
		Duration:        25 * time.Millisecond,
	}}
	p := &Provider{scanner: scanner, inventory: &fakeInventory{items: []devices.Device{device}}}

	result, err := p.InspectPorts(context.Background(), PortInspectionRequest{
		DeviceID: device.ID,
		Profile:  PortInspectionServices,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanner.inspectionAddress != device.IP || scanner.inspectionTCPProfile != internalscanner.TCPProfileServices {
		t.Fatalf("scanner target = %s %q", scanner.inspectionAddress, scanner.inspectionTCPProfile)
	}
	if result.DeviceID != device.ID || result.IP != device.IP || !result.Reachable || result.Cached || result.PortsProbed != 23 || result.PeakConcurrency != 16 {
		t.Fatalf("result = %#v", result)
	}
	if got := result.OpenPorts; len(got) != 2 || got[0] != 22 || got[1] != 443 {
		t.Fatalf("open ports = %v", got)
	}
}

func TestProviderPortInspectionRequiresInventoriedDeviceAndValidProfile(t *testing.T) {
	scanner := &fakeScanner{}
	p := &Provider{scanner: scanner, inventory: &fakeInventory{}}
	if _, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: "dev_missing"}); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("missing device error = %v", err)
	}
	_, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: "dev_missing", Profile: "everything"})
	var invalid *InvalidPortInspectionError
	if !errors.As(err, &invalid) {
		t.Fatalf("invalid profile error = %T %v", err, err)
	}
	if scanner.inspectionCalls.Load() != 0 {
		t.Fatalf("scanner calls = %d, want zero", scanner.inspectionCalls.Load())
	}
}

func TestProviderCachesAndRefreshesPortInspections(t *testing.T) {
	now := time.Date(2026, time.July, 18, 14, 0, 0, 0, time.UTC)
	device := devices.Device{ID: "dev_test", IP: netip.MustParseAddr("192.0.2.10")}
	scanner := &fakeScanner{inspection: internalscanner.TCPInspection{OpenPorts: []uint16{443}, PortsProbed: 23}}
	p := &Provider{
		scanner:       scanner,
		inventory:     &fakeInventory{items: []devices.Device{device}},
		inspectionTTL: 5 * time.Minute,
		inspectionNow: func() time.Time { return now },
	}

	first, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: device.ID})
	if err != nil {
		t.Fatal(err)
	}
	first.OpenPorts[0] = 9999
	cached, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: device.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !cached.Cached || cached.OpenPorts[0] != 443 || scanner.inspectionCalls.Load() != 1 {
		t.Fatalf("cached result = %#v; calls = %d", cached, scanner.inspectionCalls.Load())
	}
	if _, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: device.ID, Refresh: true}); err != nil {
		t.Fatal(err)
	}
	if scanner.inspectionCalls.Load() != 2 {
		t.Fatalf("refresh calls = %d, want 2", scanner.inspectionCalls.Load())
	}
	now = now.Add(6 * time.Minute)
	if _, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: device.ID}); err != nil {
		t.Fatal(err)
	}
	if scanner.inspectionCalls.Load() != 3 {
		t.Fatalf("expired cache calls = %d, want 3", scanner.inspectionCalls.Load())
	}
}

func TestProviderCoalescesConcurrentPortInspections(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	device := devices.Device{ID: "dev_test", IP: netip.MustParseAddr("192.0.2.10")}
	scanner := &fakeScanner{
		inspection:        internalscanner.TCPInspection{OpenPorts: []uint16{22}},
		inspectionStarted: started,
		inspectionRelease: release,
	}
	p := &Provider{scanner: scanner, inventory: &fakeInventory{items: []devices.Device{device}}}
	results := make(chan PortInspectionResult, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			result, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: device.ID})
			results <- result
			errors <- err
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("inspection did not start")
	}
	close(release)
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
		<-results
	}
	if scanner.inspectionCalls.Load() != 1 {
		t.Fatalf("scanner calls = %d, want one", scanner.inspectionCalls.Load())
	}
}

func TestProviderDoesNotCacheFailedPortInspection(t *testing.T) {
	device := devices.Device{ID: "dev_test", IP: netip.MustParseAddr("192.0.2.10")}
	scanner := &fakeScanner{inspectionErr: errors.New("probe failure")}
	p := &Provider{scanner: scanner, inventory: &fakeInventory{items: []devices.Device{device}}}
	for range 2 {
		if _, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: device.ID}); err == nil {
			t.Fatal("failed inspection returned no error")
		}
	}
	if scanner.inspectionCalls.Load() != 2 {
		t.Fatalf("scanner calls = %d, want failed results uncached", scanner.inspectionCalls.Load())
	}
}

func TestProviderInvalidatesPortInspectionWhenDeviceAddressChanges(t *testing.T) {
	device := devices.Device{ID: "dev_test", IP: netip.MustParseAddr("192.0.2.10")}
	inventory := &fakeInventory{items: []devices.Device{device}}
	scanner := &fakeScanner{inspection: internalscanner.TCPInspection{OpenPorts: []uint16{22}}}
	p := &Provider{scanner: scanner, inventory: inventory}
	if _, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: device.ID}); err != nil {
		t.Fatal(err)
	}
	inventory.mu.Lock()
	inventory.items[0].IP = netip.MustParseAddr("192.0.2.25")
	inventory.mu.Unlock()
	result, err := p.InspectPorts(context.Background(), PortInspectionRequest{DeviceID: device.ID})
	if err != nil {
		t.Fatal(err)
	}
	if result.Cached || result.IP.String() != "192.0.2.25" || scanner.inspectionCalls.Load() != 2 {
		t.Fatalf("result = %#v; calls = %d", result, scanner.inspectionCalls.Load())
	}
}

func TestProviderInstallsDocker(t *testing.T) {
	installer := &fakeDockerInstaller{result: dockerinstaller.Result{
		Status:  dockerinstaller.StatusInstalled,
		Version: "Docker version 28.0.1",
	}}
	p := &Provider{dockerInstaller: installer}
	target := DockerInstallTarget{Host: "node.local", User: "operator", Port: 2222}

	result, err := p.InstallDocker(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if installer.host != target.Host || installer.user != target.User || installer.port != target.Port {
		t.Fatalf("installer target = %q %q %d", installer.host, installer.user, installer.port)
	}
	if result.Target != target || result.Status != DockerInstalled || result.Version != "Docker version 28.0.1" {
		t.Fatalf("result = %#v", result)
	}
}

func TestProviderMapsInvalidDeploymentTarget(t *testing.T) {
	p := &Provider{dockerInstaller: &fakeDockerInstaller{
		err: &dockerinstaller.InvalidTargetError{Reason: "deployment host is required"},
	}}
	_, err := p.InstallDocker(context.Background(), DockerInstallTarget{})
	var invalid *InvalidDeploymentTargetError
	if !errors.As(err, &invalid) || invalid.Reason != "deployment host is required" {
		t.Fatalf("error = %T %v", err, err)
	}
}

func TestProviderAllowsOnlyOneDockerDeployment(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	p := &Provider{dockerInstaller: &fakeDockerInstaller{started: started, release: release}}
	done := make(chan error, 1)
	go func() {
		_, err := p.InstallDocker(context.Background(), DockerInstallTarget{Host: "node-1"})
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("deployment did not start")
	}
	if _, err := p.InstallDocker(context.Background(), DockerInstallTarget{Host: "node-2"}); !errors.Is(err, ErrDeploymentInProgress) {
		t.Fatalf("second deployment error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
