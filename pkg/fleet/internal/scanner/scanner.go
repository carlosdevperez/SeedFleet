// Package scanner discovers devices on a bounded local IPv4 network.
package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

// Config controls bounded network activity and provides seams for tests.
type Config struct {
	TCPPortRange        PortRange
	UDPPortRange        PortRange
	DiscoveryPorts      []uint16
	Timeout             time.Duration
	PortTimeout         time.Duration
	Concurrency         int
	ProbeConcurrency    int
	MaxAddresses        uint64
	ResolveNames        bool
	AllowedNetworks     []netip.Prefix
	AllowRoutedNetworks bool
	InterfacePrefixes   func() ([]netip.Prefix, error)
	NeighborSource      NeighborSource
	IdentitySources     []IdentitySource
	DialContext         func(context.Context, string, string) (net.Conn, error)
	Aliases             map[string]DeviceAlias
}

// Result is one complete network observation.
type Result struct {
	Network string
	Devices []devices.Device
}

// DefaultConfig returns the production scanner configuration.
func DefaultConfig() Config {
	return Config{
		TCPPortRange:     allPorts,
		UDPPortRange:     allPorts,
		DiscoveryPorts:   []uint16{22, 80, 443, 445, 3389},
		Timeout:          300 * time.Millisecond,
		PortTimeout:      100 * time.Millisecond,
		Concurrency:      64,
		ProbeConcurrency: 256,
		MaxAddresses:     4096,
		ResolveNames:     true,
	}
}

// Scanner discovers devices without retaining inventory state.
type Scanner struct {
	config            Config
	interfacePrefixes func() ([]netip.Prefix, error)
	neighbors         NeighborSource
	identities        []IdentitySource
}

// New returns a scanner configured with the supplied discovery sources.
func New(config Config) *Scanner {
	config.Aliases = normalizeAliases(config.Aliases)
	config.DiscoveryPorts = append([]uint16(nil), config.DiscoveryPorts...)
	config.AllowedNetworks = append([]netip.Prefix(nil), config.AllowedNetworks...)
	for index := range config.AllowedNetworks {
		if config.AllowedNetworks[index].IsValid() {
			config.AllowedNetworks[index] = config.AllowedNetworks[index].Masked()
		}
	}
	interfacePrefixes := config.InterfacePrefixes
	if interfacePrefixes == nil {
		interfacePrefixes = systemInterfacePrefixes
	}
	neighbors := config.NeighborSource
	if neighbors == nil {
		neighbors = newSystemNeighborSource()
	}
	identities := config.IdentitySources
	if identities == nil {
		identities = []IdentitySource{
			newLocalIdentitySource(),
			newSSDPIdentitySource(config.Timeout, config.Concurrency),
			newMDNSIdentitySource(config.Timeout),
		}
	}
	return &Scanner{
		config:            config,
		interfacePrefixes: interfacePrefixes,
		neighbors:         neighbors,
		identities:        identities,
	}
}

// ValidateNetwork validates and returns the canonical masked CIDR without
// sending network traffic.
func (s *Scanner) ValidateNetwork(network string) (string, error) {
	prefix, _, err := s.prepareNetwork(network)
	if err != nil {
		return "", err
	}
	return prefix.String(), nil
}

func (s *Scanner) validateConfig() error {
	if s.config.Concurrency < 1 {
		return errors.New("scanner concurrency must be at least 1")
	}
	if err := s.config.TCPPortRange.validate("TCP"); err != nil {
		return err
	}
	if err := s.config.UDPPortRange.validate("UDP"); err != nil {
		return err
	}
	for _, port := range s.config.DiscoveryPorts {
		if port == 0 {
			return errors.New("TCP discovery ports must be between 1 and 65535")
		}
	}
	if len(s.config.DiscoveryPorts) > 0 && s.config.Timeout <= 0 {
		return errors.New("TCP discovery timeout must be greater than zero")
	}
	if (s.config.TCPPortRange.enabled() || s.config.UDPPortRange.enabled()) && s.config.PortTimeout <= 0 {
		return errors.New("port probe timeout must be greater than zero")
	}
	return nil
}

// Scan discovers and returns devices in network. Independent naming sources
// are best effort; cancellation and invalid configuration are returned.
func (s *Scanner) Scan(ctx context.Context, network string) (Result, error) {
	prefix, count, err := s.prepareNetwork(network)
	if err != nil {
		return Result{}, err
	}

	identityResults := s.startIdentitySources(ctx, prefix)
	addresses := usableAddresses(prefix, count)
	portResults := s.startPortScan(ctx, addresses)
	discovery, err := s.scanTCPDiscovery(ctx, addresses)
	if err != nil {
		return Result{}, err
	}
	foundByIP := make(map[netip.Addr]devices.Device)
	applyPortScan(foundByIP, portScan{tcp: discovery, tcpScanned: len(s.config.DiscoveryPorts) > 0})
	if err := s.scanNeighbors(ctx, prefix, count, foundByIP); err != nil {
		return Result{}, err
	}
	ports := <-portResults
	if ports.err != nil {
		return Result{}, ports.err
	}
	applyPortScan(foundByIP, ports)
	if s.config.ResolveNames {
		applyIdentities(foundByIP, prefix, count, collectIdentities(identityResults, len(s.identities)))
		if err := s.resolveHostnames(ctx, foundByIP); err != nil {
			return Result{}, err
		}
	}
	finalizeDeviceNames(foundByIP)

	found := make([]devices.Device, 0, len(foundByIP))
	for _, item := range foundByIP {
		found = append(found, item)
	}
	sort.Slice(found, func(i, j int) bool {
		return found[i].IP.Compare(found[j].IP) < 0
	})
	return Result{Network: prefix.String(), Devices: found}, nil
}
