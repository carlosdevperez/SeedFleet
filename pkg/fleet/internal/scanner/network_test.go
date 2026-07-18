package scanner

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestValidateNetwork(t *testing.T) {
	prefix, count, err := validateNetwork("192.0.2.23/24", 256)
	if err != nil {
		t.Fatal(err)
	}
	if got := prefix.String(); got != "192.0.2.0/24" {
		t.Fatalf("prefix = %s, want 192.0.2.0/24", got)
	}
	if count != 256 {
		t.Fatalf("count = %d, want 256", count)
	}
}

func TestScannerAcceptsOnlyDirectlyConnectedNetworksByDefault(t *testing.T) {
	config := Config{
		Ports: []uint16{80}, Timeout: time.Millisecond, Concurrency: 1, MaxAddresses: 4096,
		InterfacePrefixes: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.4/24")}, nil
		},
	}
	scanner := New(config)
	canonical, err := scanner.ValidateNetwork("192.168.1.190/25")
	if err != nil {
		t.Fatalf("direct subnetwork rejected: %v", err)
	}
	if canonical != "192.168.1.128/25" {
		t.Fatalf("canonical network = %q", canonical)
	}
	_, err = scanner.ValidateNetwork("192.168.2.0/24")
	var invalid *InvalidNetworkError
	if !errors.As(err, &invalid) {
		t.Fatalf("non-direct error = %T %v", err, err)
	}
}

func TestScannerEnforcesAllowlist(t *testing.T) {
	config := Config{
		Ports: []uint16{80}, Timeout: time.Millisecond, Concurrency: 1, MaxAddresses: 4096,
		AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/25")},
		InterfacePrefixes: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil
		},
	}
	scanner := New(config)
	if _, err := scanner.ValidateNetwork("192.168.1.0/26"); err != nil {
		t.Fatalf("allowlisted subnetwork rejected: %v", err)
	}
	if _, err := scanner.ValidateNetwork("192.168.1.128/25"); err == nil {
		t.Fatal("network outside allowlist accepted")
	}
}

func TestScannerAllowsExplicitlyAllowlistedRoutedNetwork(t *testing.T) {
	scanner := New(Config{
		Ports: []uint16{80}, Timeout: time.Millisecond, Concurrency: 1, MaxAddresses: 4096,
		AllowedNetworks:     []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		AllowRoutedNetworks: true,
		InterfacePrefixes: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil
		},
	})
	if _, err := scanner.ValidateNetwork("10.20.1.0/24"); err != nil {
		t.Fatalf("explicit routed network rejected: %v", err)
	}
}

func TestScannerRejectsRoutedModeWithoutAllowlist(t *testing.T) {
	scanner := New(Config{
		Ports: []uint16{80}, Timeout: time.Millisecond, Concurrency: 1, MaxAddresses: 4096,
		AllowRoutedNetworks: true,
	})
	if _, err := scanner.ValidateNetwork("192.168.1.0/24"); err == nil {
		t.Fatal("unsafe routed configuration accepted")
	}
}

func TestValidateNetworkRejectsTooLargeAndIPv6(t *testing.T) {
	if _, _, err := validateNetwork("10.0.0.0/8", 4096); err == nil {
		t.Fatal("expected an oversized network error")
	}
	if _, _, err := validateNetwork("2001:db8::/64", 4096); err == nil {
		t.Fatal("expected an IPv6 error")
	}
}

func TestForEachUsableAddress(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/30")
	var addresses []string
	forEachUsableAddress(prefix, 4, func(address netip.Addr) bool {
		addresses = append(addresses, address.String())
		return true
	})

	want := []string{"192.0.2.1", "192.0.2.2"}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("addresses = %v, want %v", addresses, want)
	}
}

func TestForEachUsableAddressIncludesBothAddressesIn31(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.8/31")
	var addresses []string
	forEachUsableAddress(prefix, 2, func(address netip.Addr) bool {
		addresses = append(addresses, address.String())
		return true
	})

	want := []string{"192.0.2.8", "192.0.2.9"}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("addresses = %v, want %v", addresses, want)
	}
}
