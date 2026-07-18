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
	DiscoveryPorts       []uint16
	Timeout              time.Duration
	PortTimeout          time.Duration
	Concurrency          int
	DiscoveryConcurrency int
	PortMinConcurrency   int
	PortMaxConcurrency   int
	MaxAddresses         uint64
	ResolveNames         bool
	AllowedNetworks      []netip.Prefix
	AllowRoutedNetworks  bool
	InterfacePrefixes    func() ([]netip.Prefix, error)
	NeighborSource       NeighborSource
	IdentitySources      []IdentitySource
	DialContext          func(context.Context, string, string) (net.Conn, error)
	Aliases              map[string]DeviceAlias
	ObserveStage         func(StageTiming)
}

// StageTiming is an internal observation of one scanner stage. Config lives in
// an internal package, so stage measurements remain an implementation detail
// instead of becoming part of the public fleet API.
type StageTiming struct {
	Stage     string
	Duration  time.Duration
	WorkItems int
}

// Result is one complete network observation.
type Result struct {
	Network string
	Devices []devices.Device
}

// DefaultConfig returns the production scanner configuration.
func DefaultConfig() Config {
	return Config{
		DiscoveryPorts:       []uint16{22, 80, 443, 445, 3389},
		Timeout:              300 * time.Millisecond,
		PortTimeout:          100 * time.Millisecond,
		Concurrency:          128,
		DiscoveryConcurrency: 512,
		PortMinConcurrency:   128,
		PortMaxConcurrency:   1024,
		MaxAddresses:         4096,
		ResolveNames:         true,
	}
}

// Scanner discovers devices without retaining inventory state.
type Scanner struct {
	config            Config
	interfacePrefixes func() ([]netip.Prefix, error)
	neighbors         NeighborSource
	identities        []IdentitySource
	discoveryDial     func(context.Context, string, string) (net.Conn, error)
	inspectionDial    func(context.Context, string, string) (net.Conn, error)
}

// New returns a scanner configured with the supplied discovery sources.
func New(config Config) *Scanner {
	if config.DiscoveryConcurrency < 1 {
		config.DiscoveryConcurrency = max(1, config.Concurrency*max(1, len(config.DiscoveryPorts)))
	}
	if config.PortMinConcurrency < 1 {
		config.PortMinConcurrency = 128
	}
	if config.PortMaxConcurrency < 1 {
		config.PortMaxConcurrency = max(1024, config.PortMinConcurrency)
	}
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
	discoveryDial := config.DialContext
	inspectionDial := config.DialContext
	if discoveryDial == nil {
		discoveryDial = (&net.Dialer{Timeout: config.Timeout}).DialContext
	}
	if inspectionDial == nil {
		inspectionDial = (&net.Dialer{Timeout: config.PortTimeout}).DialContext
	}
	return &Scanner{
		config:            config,
		interfacePrefixes: interfacePrefixes,
		neighbors:         neighbors,
		identities:        identities,
		discoveryDial:     discoveryDial,
		inspectionDial:    inspectionDial,
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
	if s.config.DiscoveryConcurrency < 1 {
		return errors.New("discovery concurrency must be at least 1")
	}
	for _, port := range s.config.DiscoveryPorts {
		if port == 0 {
			return errors.New("TCP discovery ports must be between 1 and 65535")
		}
	}
	if len(s.config.DiscoveryPorts) > 0 && s.config.Timeout <= 0 {
		return errors.New("TCP discovery timeout must be greater than zero")
	}
	return nil
}

// Scan discovers and returns devices in network. Independent naming sources
// are best effort; cancellation and invalid configuration are returned.
func (s *Scanner) Scan(ctx context.Context, network string) (Result, error) {
	started := time.Now()
	prefix, count, err := s.prepareNetwork(network)
	if err != nil {
		return Result{}, err
	}

	identityResults := s.startIdentitySources(ctx, prefix)
	addresses := usableAddresses(prefix, count)
	discoveryStarted := time.Now()
	discovery, err := s.scanTCPDiscovery(ctx, addresses)
	if err != nil {
		return Result{}, err
	}
	s.observeStage("tcp-discovery", discoveryStarted, len(addresses)*len(s.config.DiscoveryPorts))
	foundByIP := make(map[netip.Addr]devices.Device)
	applyPortScan(foundByIP, portScan{tcp: discovery, tcpScanned: len(s.config.DiscoveryPorts) > 0})
	neighborStarted := time.Now()
	if err := s.scanNeighbors(ctx, prefix, count, foundByIP); err != nil {
		return Result{}, err
	}
	s.observeStage("neighbors", neighborStarted, len(foundByIP))
	if s.config.ResolveNames {
		identityStarted := time.Now()
		applyIdentities(foundByIP, prefix, count, collectIdentities(identityResults, len(s.identities)))
		s.observeStage("identity", identityStarted, len(foundByIP))
		reverseStarted := time.Now()
		if err := s.resolveHostnames(ctx, foundByIP); err != nil {
			return Result{}, err
		}
		s.observeStage("reverse-dns", reverseStarted, len(foundByIP))
	}
	finalizeDeviceNames(foundByIP)

	found := make([]devices.Device, 0, len(foundByIP))
	for _, item := range foundByIP {
		found = append(found, item)
	}
	sort.Slice(found, func(i, j int) bool {
		return found[i].IP.Compare(found[j].IP) < 0
	})
	s.observeStage("scan-total", started, len(addresses))
	return Result{Network: prefix.String(), Devices: found}, nil
}

func (s *Scanner) observeStage(stage string, started time.Time, workItems int) {
	if s.config.ObserveStage != nil {
		s.config.ObserveStage(StageTiming{Stage: stage, Duration: time.Since(started), WorkItems: workItems})
	}
}
