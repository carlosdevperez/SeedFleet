package scanner

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestTCPDiscoveryUsesConfiguredConcurrency(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	scanner := New(Config{
		DiscoveryPorts:       []uint16{80, 81},
		Timeout:              time.Second,
		Concurrency:          2,
		DiscoveryConcurrency: 4,
		MaxAddresses:         4,
		InterfacePrefixes:    testInterfacePrefixes,
		NeighborSource:       fakeNeighborSource{},
		IdentitySources:      []IdentitySource{},
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
			case <-time.After(20 * time.Millisecond):
				return nil, syscall.ECONNREFUSED
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})

	result, err := scanner.Scan(context.Background(), "192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Devices) != 2 {
		t.Fatalf("found %d devices, want 2", len(result.Devices))
	}
	if got := maximum.Load(); got != 4 {
		t.Fatalf("maximum concurrent probes = %d, want 4", got)
	}
}
