package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

type fakeNeighborSource struct {
	neighbors []Neighbor
	err       error
}

func (source fakeNeighborSource) List(context.Context) ([]Neighbor, error) {
	return source.neighbors, source.err
}

type fakeIdentitySource struct {
	identities []Identity
	err        error
}

func (source fakeIdentitySource) Discover(context.Context, netip.Prefix) ([]Identity, error) {
	return source.identities, source.err
}

func testInterfacePrefixes() ([]netip.Prefix, error) {
	return []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, nil
}

func TestScanIncludesQuietHostFromNeighborTable(t *testing.T) {
	scanner := New(Config{
		Timeout:           time.Nanosecond,
		Concurrency:       2,
		MaxAddresses:      4,
		InterfacePrefixes: testInterfacePrefixes,
		NeighborSource: fakeNeighborSource{neighbors: []Neighbor{
			{IP: netip.MustParseAddr("192.0.2.2"), MAC: mustParseMAC(t, "e0:ef:bf:ad:56:3c")},
			{IP: netip.MustParseAddr("198.51.100.2"), MAC: mustParseMAC(t, "aa:bb:cc:dd:ee:ff")},
		}},
	})

	result, err := scanner.Scan(context.Background(), "192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	found := result.Devices
	if len(found) != 1 {
		t.Fatalf("found %d devices, want 1: %#v", len(found), found)
	}
	if got := found[0].IP.String(); got != "192.0.2.2" {
		t.Fatalf("IP = %s, want 192.0.2.2", got)
	}
	if got := found[0].MAC; got != "e0:ef:bf:ad:56:3c" {
		t.Fatalf("MAC = %s, want e0:ef:bf:ad:56:3c", got)
	}
	if !reflect.DeepEqual(found[0].DiscoveredBy, []string{"neighbor"}) {
		t.Fatalf("DiscoveredBy = %v, want [neighbor]", found[0].DiscoveredBy)
	}
}

func TestScanReadsNeighborsBeforeFullPortSweepCompletes(t *testing.T) {
	fullSweepStarted := make(chan struct{})
	neighborRead := make(chan struct{}, 1)
	releaseFullSweep := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFullSweep) }) }
	defer release()

	address := netip.MustParseAddr("192.0.2.1")
	scanner := New(Config{
		TCPPortRange:      PortRange{First: 1, Last: 1},
		DiscoveryPorts:    []uint16{80},
		Timeout:           time.Second,
		PortTimeout:       time.Second,
		Concurrency:       1,
		ProbeConcurrency:  1,
		MaxAddresses:      1,
		InterfacePrefixes: testInterfacePrefixes,
		NeighborSource: signalingNeighborSource{
			called:    neighborRead,
			neighbors: []Neighbor{{IP: address, MAC: mustParseMAC(t, "e0:ef:bf:ad:56:3c")}},
		},
		IdentitySources: []IdentitySource{},
		DialContext: func(ctx context.Context, _, endpoint string) (net.Conn, error) {
			if endpoint != "192.0.2.1:1" {
				return nil, errors.New("probe timed out")
			}
			close(fullSweepStarted)
			select {
			case <-releaseFullSweep:
				return nil, errors.New("probe timed out")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})

	type scanResult struct {
		result Result
		err    error
	}
	completed := make(chan scanResult, 1)
	go func() {
		result, err := scanner.Scan(context.Background(), "192.0.2.1/32")
		completed <- scanResult{result: result, err: err}
	}()

	select {
	case <-fullSweepStarted:
	case <-time.After(time.Second):
		t.Fatal("full port sweep did not start")
	}
	select {
	case <-neighborRead:
	case <-time.After(time.Second):
		t.Fatal("neighbor table was not read while full port sweep was active")
	}
	select {
	case result := <-completed:
		t.Fatalf("scan completed before the full sweep was released: %v", result.err)
	default:
	}

	release()
	select {
	case result := <-completed:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if len(result.result.Devices) != 1 || result.result.Devices[0].IP != address {
			t.Fatalf("devices = %#v, want neighbor %s", result.result.Devices, address)
		}
	case <-time.After(time.Second):
		t.Fatal("scan did not complete after the full sweep was released")
	}
}

type signalingNeighborSource struct {
	called    chan<- struct{}
	neighbors []Neighbor
}

func (source signalingNeighborSource) List(context.Context) ([]Neighbor, error) {
	source.called <- struct{}{}
	return source.neighbors, nil
}

func TestScanIncludesHostFromNameDiscovery(t *testing.T) {
	scanner := New(Config{
		Timeout:           time.Nanosecond,
		Concurrency:       2,
		MaxAddresses:      4,
		ResolveNames:      true,
		InterfacePrefixes: testInterfacePrefixes,
		NeighborSource:    fakeNeighborSource{},
		IdentitySources: []IdentitySource{fakeIdentitySource{identities: []Identity{
			{IP: netip.MustParseAddr("192.0.2.2"), Hostname: "speaker.local", Method: "mdns"},
		}}},
	})

	result, err := scanner.Scan(context.Background(), "192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	found := result.Devices
	if len(found) != 1 {
		t.Fatalf("found %d devices, want 1: %#v", len(found), found)
	}
	if found[0].Hostname != "speaker.local" {
		t.Fatalf("Hostname = %q, want speaker.local", found[0].Hostname)
	}
	if !reflect.DeepEqual(found[0].DiscoveredBy, []string{"mdns"}) {
		t.Fatalf("DiscoveredBy = %v, want [mdns]", found[0].DiscoveredBy)
	}
}

func TestScanPrefersAliasIdentity(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:ff"
	address := netip.MustParseAddr("192.0.2.2")
	scanner := New(Config{
		Timeout:           time.Nanosecond,
		Concurrency:       2,
		MaxAddresses:      4,
		ResolveNames:      true,
		InterfacePrefixes: testInterfacePrefixes,
		NeighborSource:    fakeNeighborSource{neighbors: []Neighbor{{IP: address, MAC: mustParseMAC(t, mac)}}},
		IdentitySources: []IdentitySource{fakeIdentitySource{identities: []Identity{{
			IP: address, Name: "Advertised name", Hostname: "advertised.local", Method: "mdns",
		}}}},
		Aliases: map[string]DeviceAlias{mac: {
			Name: "Stable name", Hostname: "stable.local", Manufacturer: "Example Corp",
		}},
	})

	result, err := scanner.Scan(context.Background(), "192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	found := result.Devices
	if len(found) != 1 {
		t.Fatalf("found %d devices, want 1", len(found))
	}
	if found[0].Name != "Stable name" || found[0].Hostname != "stable.local" || found[0].Manufacturer != "Example Corp" {
		t.Fatalf("identity = %#v, want alias fields", found[0])
	}
	if !reflect.DeepEqual(found[0].DiscoveredBy, []string{"neighbor", "alias", "mdns"}) {
		t.Fatalf("DiscoveredBy = %v", found[0].DiscoveredBy)
	}
}

func TestScanClassifiesInvalidNetworkInput(t *testing.T) {
	scanner := New(DefaultConfig())
	_, err := scanner.Scan(context.Background(), "not-a-cidr")
	var invalidNetwork *InvalidNetworkError
	if !errors.As(err, &invalidNetwork) {
		t.Fatalf("error = %T %v, want InvalidNetworkError", err, err)
	}
}

func TestScanIgnoresUnavailableOptionalSources(t *testing.T) {
	scanner := New(Config{
		Timeout:           time.Nanosecond,
		Concurrency:       2,
		MaxAddresses:      4,
		ResolveNames:      true,
		InterfacePrefixes: testInterfacePrefixes,
		NeighborSource:    fakeNeighborSource{err: errors.New("neighbor unavailable")},
		IdentitySources: []IdentitySource{
			fakeIdentitySource{err: errors.New("multicast unavailable")},
		},
	})

	result, err := scanner.Scan(context.Background(), "192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Devices) != 0 {
		t.Fatalf("devices = %#v, want none", result.Devices)
	}
}

func mustParseMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}
