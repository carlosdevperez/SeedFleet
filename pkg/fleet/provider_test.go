package fleet

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
	internalscanner "github.com/carlosdevperez/seedfleet/pkg/fleet/internal/scanner"
)

type fakeScanner struct {
	result  internalscanner.Result
	err     error
	started chan struct{}
	release chan struct{}
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

type fakeInventory struct {
	mu    sync.Mutex
	items []devices.Device
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
