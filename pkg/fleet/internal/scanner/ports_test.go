package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDefaultConfigSweepsEveryTCPAndUDPPort(t *testing.T) {
	config := DefaultConfig()
	want := PortRange{First: 1, Last: 65535}
	if config.TCPPortRange != want || config.UDPPortRange != want {
		t.Fatalf("port ranges = TCP %#v, UDP %#v; want %#v", config.TCPPortRange, config.UDPPortRange, want)
	}
	if config.TCPPortRange.count() != 65535 || config.UDPPortRange.count() != 65535 {
		t.Fatalf("port counts = TCP %d, UDP %d; want 65535 each", config.TCPPortRange.count(), config.UDPPortRange.count())
	}
	wantDiscovery := []uint16{22, 80, 443, 445, 3389}
	if !reflect.DeepEqual(config.DiscoveryPorts, wantDiscovery) {
		t.Fatalf("discovery ports = %v, want %v", config.DiscoveryPorts, wantDiscovery)
	}
}

func TestPortJobQueueIncludesAddressesAndRangeEndpoints(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	secondAddress := netip.MustParseAddr("192.0.2.2")
	jobs := newPortJobQueue([]netip.Addr{address, secondAddress}, PortRange{First: 65534, Last: 65535})

	var found []probeJob
	for {
		job, ok := jobs.take()
		if !ok {
			break
		}
		found = append(found, job)
	}
	want := []probeJob{
		{address: address, port: 65534},
		{address: address, port: 65535},
		{address: secondAddress, port: 65534},
		{address: secondAddress, port: 65535},
	}
	if !reflect.DeepEqual(found, want) {
		t.Fatalf("jobs = %#v, want %#v", found, want)
	}
}

func TestTCPAndUDPPortSweepsRunConcurrently(t *testing.T) {
	entered := make(chan string, 2)
	release := make(chan struct{})
	scanner := New(Config{
		TCPPortRange:     PortRange{First: 1, Last: 1},
		UDPPortRange:     PortRange{First: 1, Last: 1},
		PortTimeout:      time.Second,
		ProbeConcurrency: 1,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			entered <- network
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if network == "udp4" {
				return &probeConn{readResponse: true}, nil
			}
			return &probeConn{}, nil
		},
	})

	result := scanner.startPortScan(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.1")})
	seen := map[string]bool{}
	for range 2 {
		select {
		case network := <-entered:
			seen[network] = true
		case <-time.After(time.Second):
			t.Fatal("TCP and UDP sweeps did not start concurrently")
		}
	}
	close(release)
	scan := <-result
	if scan.err != nil {
		t.Fatal(scan.err)
	}
	if !seen["tcp"] || !seen["udp4"] {
		t.Fatalf("dialed networks = %v, want tcp and udp4", seen)
	}
}

func TestScanFindsDevicesThroughAllPortTCPAndUDPProbes(t *testing.T) {
	scanner := New(Config{
		TCPPortRange:      PortRange{First: 2, Last: 3},
		UDPPortRange:      PortRange{First: 4, Last: 5},
		Timeout:           time.Millisecond,
		PortTimeout:       time.Second,
		Concurrency:       2,
		ProbeConcurrency:  4,
		MaxAddresses:      4,
		InterfacePrefixes: testInterfacePrefixes,
		NeighborSource:    fakeNeighborSource{},
		IdentitySources:   []IdentitySource{},
		DialContext: func(_ context.Context, network, endpoint string) (net.Conn, error) {
			host, rawPort, err := net.SplitHostPort(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(rawPort)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case network == "tcp" && host == "192.0.2.1" && port == 3:
				return &probeConn{}, nil
			case network == "udp4" && host == "192.0.2.2" && port == 5:
				return &probeConn{readResponse: true}, nil
			case network == "udp4":
				return &probeConn{readErr: timeoutError{}}, nil
			default:
				return nil, errors.New("probe timed out")
			}
		},
	})

	result, err := scanner.Scan(context.Background(), "192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Devices) != 2 {
		t.Fatalf("devices = %#v, want two", result.Devices)
	}
	tcpDevice := result.Devices[0]
	if tcpDevice.IP.String() != "192.0.2.1" || !reflect.DeepEqual(tcpDevice.OpenPorts, []uint16{3}) || len(tcpDevice.OpenUDPPorts) != 0 {
		t.Fatalf("TCP device = %#v, want 192.0.2.1 with TCP port 3", tcpDevice)
	}
	if !reflect.DeepEqual(tcpDevice.DiscoveredBy, []string{"tcp"}) {
		t.Fatalf("TCP discovered by = %v, want [tcp]", tcpDevice.DiscoveredBy)
	}
	udpDevice := result.Devices[1]
	if udpDevice.IP.String() != "192.0.2.2" || len(udpDevice.OpenPorts) != 0 || !reflect.DeepEqual(udpDevice.OpenUDPPorts, []uint16{5}) {
		t.Fatalf("UDP device = %#v, want 192.0.2.2 with UDP port 5", udpDevice)
	}
	if !reflect.DeepEqual(udpDevice.DiscoveredBy, []string{"udp"}) {
		t.Fatalf("UDP discovered by = %v, want [udp]", udpDevice.DiscoveredBy)
	}
}

func TestUDPPortsAreProbedWithBoundedConcurrency(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	scanner := New(Config{
		UDPPortRange:     PortRange{First: 1, Last: 6},
		PortTimeout:      time.Second,
		ProbeConcurrency: 3,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return &probeConn{
				readResponse: true,
				beforeRead: func() {
					current := active.Add(1)
					for {
						previous := maximum.Load()
						if current <= previous || maximum.CompareAndSwap(previous, current) {
							break
						}
					}
				},
				afterRead: func() { active.Add(-1) },
				readDelay: 20 * time.Millisecond,
			}, nil
		},
	})

	ports, err := scanner.scanUDPPorts(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	if got := maximum.Load(); got != 3 {
		t.Fatalf("maximum concurrent probes = %d, want 3", got)
	}
	if len(ports.open[netip.MustParseAddr("192.0.2.1")]) != 6 {
		t.Fatalf("open UDP ports = %v, want six", ports)
	}
}

func TestUDPProbeReportsOnlyRepliesAsOpen(t *testing.T) {
	tests := []struct {
		name          string
		readErr       error
		readResponse  bool
		wantOpen      bool
		wantReachable bool
	}{
		{name: "reply", readResponse: true, wantOpen: true, wantReachable: true},
		{name: "closed", readErr: syscall.ECONNREFUSED, wantReachable: true},
		{name: "silent", readErr: timeoutError{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := New(Config{
				PortTimeout: time.Second,
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return &probeConn{readResponse: test.readResponse, readErr: test.readErr}, nil
				},
			})
			open, reachable := scanner.probeUDPPort(context.Background(), netip.MustParseAddr("192.0.2.1"), 53)
			if open != test.wantOpen || reachable != test.wantReachable {
				t.Fatalf("probe = open %t, reachable %t; want %t, %t", open, reachable, test.wantOpen, test.wantReachable)
			}
		})
	}
}

type probeConn struct {
	readResponse bool
	readErr      error
	readDelay    time.Duration
	beforeRead   func()
	afterRead    func()
}

func (connection *probeConn) Read(buffer []byte) (int, error) {
	if connection.beforeRead != nil {
		connection.beforeRead()
	}
	if connection.afterRead != nil {
		defer connection.afterRead()
	}
	if connection.readDelay > 0 {
		time.Sleep(connection.readDelay)
	}
	if connection.readErr != nil {
		return 0, connection.readErr
	}
	if connection.readResponse && len(buffer) > 0 {
		buffer[0] = 1
		return 1, nil
	}
	return 0, nil
}

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

type timeoutError struct{}

func (timeoutError) Error() string   { return "timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
