package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDefaultConfigUsesFastDiscoveryAndAdaptiveInspectionPools(t *testing.T) {
	config := DefaultConfig()
	wantDiscovery := []uint16{22, 80, 443, 445, 3389}
	if !reflect.DeepEqual(config.DiscoveryPorts, wantDiscovery) {
		t.Fatalf("discovery ports = %v, want %v", config.DiscoveryPorts, wantDiscovery)
	}
	if config.DiscoveryConcurrency != 512 {
		t.Fatalf("discovery concurrency = %d, want 512", config.DiscoveryConcurrency)
	}
	if config.PortMinConcurrency != 128 || config.PortMaxConcurrency != 1024 {
		t.Fatalf("inspection concurrency = %d..%d, want 128..1024", config.PortMinConcurrency, config.PortMaxConcurrency)
	}
}

func TestTCPInspectionProfilesAreBoundedAndExplicit(t *testing.T) {
	tests := []struct {
		profile TCPProfile
		count   int
	}{
		{profile: TCPProfileServices, count: len(serviceTCPPorts)},
		{profile: TCPProfileCommon, count: 1024 + countPortsAbove(serviceTCPPorts, 1024)},
		{profile: TCPProfileFull, count: 65535},
	}
	for _, test := range tests {
		t.Run(string(test.profile), func(t *testing.T) {
			ports, err := tcpPortsForProfile(test.profile)
			if err != nil {
				t.Fatal(err)
			}
			if len(ports) != test.count || ports[0] == 0 {
				t.Fatalf("ports = %d entries starting at %d, want %d nonzero entries", len(ports), ports[0], test.count)
			}
			if !sortIsStrict(ports) {
				t.Fatalf("ports are not sorted and unique: %v", ports)
			}
		})
	}
	if _, err := tcpPortsForProfile("unknown"); err == nil {
		t.Fatal("unknown profile was accepted")
	}
}

func countPortsAbove(ports []uint16, boundary uint16) int {
	count := 0
	for _, port := range ports {
		if port > boundary {
			count++
		}
	}
	return count
}

func sortIsStrict(ports []uint16) bool {
	for index := 1; index < len(ports); index++ {
		if ports[index] <= ports[index-1] {
			return false
		}
	}
	return true
}

func TestPortJobQueueInterleavesAddresses(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	jobs := newPortJobQueue([]netip.Addr{first, second}, []uint16{80, 443})

	var found []probeJob
	for {
		job, ok := jobs.take()
		if !ok {
			break
		}
		found = append(found, job)
	}
	want := []probeJob{
		{address: first, port: 80},
		{address: second, port: 80},
		{address: first, port: 443},
		{address: second, port: 443},
	}
	if !reflect.DeepEqual(found, want) {
		t.Fatalf("jobs = %#v, want %#v", found, want)
	}
}

func TestInspectTCPUsesSelectedProfile(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.10")
	var probes atomic.Int32
	scanner := New(Config{
		PortTimeout:        time.Second,
		PortMinConcurrency: 4,
		PortMaxConcurrency: 16,
		DialContext: func(_ context.Context, network, endpoint string) (net.Conn, error) {
			if network != "tcp" {
				t.Fatalf("network = %q, want tcp", network)
			}
			probes.Add(1)
			_, rawPort, err := net.SplitHostPort(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(rawPort)
			if err != nil {
				t.Fatal(err)
			}
			if port == 443 || port == 8443 {
				return &probeConn{}, nil
			}
			return nil, syscall.ECONNREFUSED
		},
	})

	result, err := scanner.InspectTCP(context.Background(), address, TCPProfileServices)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.OpenPorts, []uint16{443, 8443}) {
		t.Fatalf("open ports = %v, want [443 8443]", result.OpenPorts)
	}
	if !result.Reachable || result.PortsProbed != len(serviceTCPPorts) || int(probes.Load()) != len(serviceTCPPorts) {
		t.Fatalf("inspection = %#v; probes = %d", result, probes.Load())
	}
}

func TestTCPInspectionConcurrencyRampsToConfiguredMaximum(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	scanner := New(Config{
		PortTimeout:        time.Second,
		PortMinConcurrency: 2,
		PortMaxConcurrency: 16,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				previous := maximum.Load()
				if current <= previous || maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			select {
			case <-time.After(time.Millisecond):
				return nil, syscall.ECONNREFUSED
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})

	result, err := scanner.InspectTCP(context.Background(), netip.MustParseAddr("192.0.2.10"), TCPProfileCommon)
	if err != nil {
		t.Fatal(err)
	}
	if result.PeakConcurrency != 16 || maximum.Load() != 16 {
		t.Fatalf("peak concurrency = result %d, observed %d; want 16", result.PeakConcurrency, maximum.Load())
	}
}

func TestFullTCPInspectionCoversEveryUsablePort(t *testing.T) {
	var probes atomic.Int32
	var first atomic.Bool
	var last atomic.Bool
	scanner := New(Config{
		PortTimeout:        time.Second,
		PortMinConcurrency: 128,
		PortMaxConcurrency: 1024,
		DialContext: func(_ context.Context, _, endpoint string) (net.Conn, error) {
			probes.Add(1)
			if strings.HasSuffix(endpoint, ":1") {
				first.Store(true)
			}
			if strings.HasSuffix(endpoint, ":65535") {
				last.Store(true)
			}
			return nil, syscall.ECONNREFUSED
		},
	})

	result, err := scanner.InspectTCP(context.Background(), netip.MustParseAddr("192.0.2.10"), TCPProfileFull)
	if err != nil {
		t.Fatal(err)
	}
	if result.PortsProbed != 65535 || probes.Load() != 65535 || !first.Load() || !last.Load() {
		t.Fatalf("inspection = %#v; probes = %d; endpoints = %t/%t", result, probes.Load(), first.Load(), last.Load())
	}
	if result.PeakConcurrency != 1024 {
		t.Fatalf("peak concurrency = %d, want 1024", result.PeakConcurrency)
	}
}

func TestTCPInspectionHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanner := New(Config{
		PortTimeout:        time.Second,
		PortMinConcurrency: 4,
		PortMaxConcurrency: 16,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if _, err := scanner.InspectTCP(ctx, netip.MustParseAddr("192.0.2.10"), TCPProfileServices); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func TestAdaptiveConcurrencyBacksOffOnCongestion(t *testing.T) {
	controller := newAdaptiveConcurrency(4, 32)
	controller.adjust(inspectionBatchStats{total: 100, timedOut: 5})
	if controller.current != 8 {
		t.Fatalf("initial ramp = %d, want 8", controller.current)
	}
	controller.adjust(inspectionBatchStats{total: 100, timedOut: 40})
	if controller.current != 4 {
		t.Fatalf("timeout backoff = %d, want 4", controller.current)
	}
	controller.current = 16
	controller.adjust(inspectionBatchStats{total: 100, timedOut: 40, resourceLimited: 1})
	if controller.current != 8 {
		t.Fatalf("resource backoff = %d, want 8", controller.current)
	}
}

func TestInspectionReportsStageTiming(t *testing.T) {
	var observed StageTiming
	scanner := New(Config{
		PortTimeout:        time.Second,
		PortMinConcurrency: 4,
		PortMaxConcurrency: 4,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, syscall.ECONNREFUSED
		},
		ObserveStage: func(timing StageTiming) { observed = timing },
	})
	if _, err := scanner.InspectTCP(context.Background(), netip.MustParseAddr("192.0.2.10"), TCPProfileServices); err != nil {
		t.Fatal(err)
	}
	if observed.Stage != "tcp-inspection" || observed.WorkItems != len(serviceTCPPorts) || observed.Duration <= 0 {
		t.Fatalf("stage timing = %#v", observed)
	}
}

func BenchmarkPortJobQueue(b *testing.B) {
	addresses := make([]netip.Addr, 254)
	address := netip.MustParseAddr("192.0.2.1")
	for index := range addresses {
		addresses[index] = address
		address = address.Next()
	}
	ports, err := tcpPortsForProfile(TCPProfileCommon)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for range b.N {
		queue := newPortJobQueue(addresses, ports)
		for {
			if _, ok := queue.take(); !ok {
				break
			}
		}
	}
}

func BenchmarkTCPInspectionScheduler(b *testing.B) {
	scanner := New(Config{
		PortTimeout:        time.Second,
		PortMinConcurrency: 128,
		PortMaxConcurrency: 1024,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, syscall.ECONNREFUSED
		},
	})
	address := netip.MustParseAddr("192.0.2.10")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := scanner.InspectTCP(context.Background(), address, TCPProfileCommon); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFastDiscoveryScheduler(b *testing.B) {
	config := DefaultConfig()
	config.ResolveNames = false
	config.InterfacePrefixes = testInterfacePrefixes
	config.NeighborSource = fakeNeighborSource{}
	config.IdentitySources = []IdentitySource{}
	config.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	}
	scanner := New(config)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := scanner.Scan(context.Background(), "192.0.2.0/24"); err != nil {
			b.Fatal(err)
		}
	}
}

type probeConn struct{}

func (*probeConn) Read([]byte) (int, error)         { return 0, nil }
func (*probeConn) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (*probeConn) Close() error                     { return nil }
func (*probeConn) LocalAddr() net.Addr              { return testAddress("local") }
func (*probeConn) RemoteAddr() net.Addr             { return testAddress("remote") }
func (*probeConn) SetDeadline(time.Time) error      { return nil }
func (*probeConn) SetReadDeadline(time.Time) error  { return nil }
func (*probeConn) SetWriteDeadline(time.Time) error { return nil }

type testAddress string

func (address testAddress) Network() string { return string(address) }
func (address testAddress) String() string  { return string(address) }
