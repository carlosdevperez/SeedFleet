package scanner

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

// PortRange is an inclusive transport port range. The zero value disables a
// protocol sweep; valid enabled ranges start at port 1 because port 0 is
// reserved and is not a usable service port.
type PortRange struct {
	First uint16
	Last  uint16
}

var allPorts = PortRange{First: 1, Last: 65535}

func (ports PortRange) enabled() bool {
	return ports.First != 0 || ports.Last != 0
}

func (ports PortRange) validate(protocol string) error {
	if !ports.enabled() {
		return nil
	}
	if ports.First == 0 || ports.Last < ports.First {
		return fmt.Errorf("%s port range must be between 1 and 65535", protocol)
	}
	return nil
}

func (ports PortRange) count() uint64 {
	if !ports.enabled() {
		return 0
	}
	return uint64(ports.Last) - uint64(ports.First) + 1
}

func boundedWorkerCount(configured, addresses int, ports PortRange) int {
	workers := configured
	if workers < 1 {
		workers = 1
	}
	jobs := uint64(addresses) * ports.count()
	if uint64(workers) > jobs {
		workers = int(jobs)
	}
	return workers
}

type portJobQueue struct {
	addresses []netip.Addr
	ports     PortRange
	portCount uint64
	total     uint64
	next      atomic.Uint64
}

func newPortJobQueue(addresses []netip.Addr, ports PortRange) *portJobQueue {
	portCount := ports.count()
	return &portJobQueue{
		addresses: addresses,
		ports:     ports,
		portCount: portCount,
		total:     uint64(len(addresses)) * portCount,
	}
}

func (jobs *portJobQueue) take() (probeJob, bool) {
	index := jobs.next.Add(1) - 1
	if index >= jobs.total {
		return probeJob{}, false
	}
	addressIndex := index / jobs.portCount
	portOffset := index % jobs.portCount
	return probeJob{
		address: jobs.addresses[addressIndex],
		port:    uint16(uint64(jobs.ports.First) + portOffset),
	}, true
}

type portScan struct {
	tcp        protocolPortScan
	udp        protocolPortScan
	tcpScanned bool
	udpScanned bool
	err        error
}

type protocolPortScan struct {
	open      map[netip.Addr][]uint16
	reachable map[netip.Addr]struct{}
}

func (s *Scanner) startPortScan(ctx context.Context, addresses []netip.Addr) <-chan portScan {
	result := make(chan portScan, 1)
	go func() {
		defer close(result)
		type protocolResult struct {
			protocol string
			scan     protocolPortScan
			err      error
		}
		protocolResults := make(chan protocolResult, 2)
		go func() {
			scan, err := s.scanTCPPorts(ctx, addresses)
			protocolResults <- protocolResult{protocol: "tcp", scan: scan, err: err}
		}()
		go func() {
			scan, err := s.scanUDPPorts(ctx, addresses)
			protocolResults <- protocolResult{protocol: "udp", scan: scan, err: err}
		}()

		scan := portScan{
			tcpScanned: s.config.TCPPortRange.enabled(),
			udpScanned: s.config.UDPPortRange.enabled(),
		}
		for range 2 {
			protocol := <-protocolResults
			if protocol.err != nil && scan.err == nil {
				scan.err = protocol.err
			}
			switch protocol.protocol {
			case "tcp":
				scan.tcp = protocol.scan
			case "udp":
				scan.udp = protocol.scan
			}
		}
		result <- scan
	}()
	return result
}

func applyPortScan(foundByIP map[netip.Addr]devices.Device, scan portScan) {
	if !scan.tcpScanned && !scan.udpScanned {
		return
	}
	now := time.Now().UTC()
	for address := range scan.tcp.reachable {
		item := foundByIP[address]
		if !item.IP.IsValid() {
			item = devices.Device{IP: address, OpenPorts: []uint16{}, OpenUDPPorts: []uint16{}, FirstSeen: now, LastSeen: now}
		}
		item.AddDiscovery("tcp")
		foundByIP[address] = item
	}
	for address := range scan.udp.reachable {
		item := foundByIP[address]
		if !item.IP.IsValid() {
			item = devices.Device{IP: address, OpenPorts: []uint16{}, OpenUDPPorts: []uint16{}, FirstSeen: now, LastSeen: now}
		}
		item.AddDiscovery("udp")
		foundByIP[address] = item
	}
	for address, item := range foundByIP {
		if scan.tcpScanned {
			item.OpenPorts = append([]uint16{}, scan.tcp.open[address]...)
		}
		if scan.udpScanned {
			item.OpenUDPPorts = append([]uint16{}, scan.udp.open[address]...)
		}
		foundByIP[address] = item
	}
}
