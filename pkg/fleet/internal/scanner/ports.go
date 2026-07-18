package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

// TCPProfile selects a bounded, private port plan for an explicit device
// inspection. Scanner configuration stays behind fleet.Provider.
type TCPProfile string

const (
	TCPProfileServices TCPProfile = "services"
	TCPProfileCommon   TCPProfile = "common"
	TCPProfileFull     TCPProfile = "full-tcp"
)

// TCPInspection is one completed targeted TCP inspection.
type TCPInspection struct {
	OpenPorts       []uint16
	Reachable       bool
	PortsProbed     int
	PeakConcurrency int
	Duration        time.Duration
}

var serviceTCPPorts = []uint16{
	22, 53, 80, 139, 443, 445, 548, 631, 1883, 2375, 2376, 3000,
	3389, 5432, 5900, 6443, 8000, 8080, 8443, 8883, 9100, 10250, 27017,
}

func tcpPortsForProfile(profile TCPProfile) ([]uint16, error) {
	switch profile {
	case TCPProfileServices:
		return append([]uint16(nil), serviceTCPPorts...), nil
	case TCPProfileCommon:
		ports := make([]uint16, 0, 1024+len(serviceTCPPorts))
		for port := 1; port <= 1024; port++ {
			ports = append(ports, uint16(port))
		}
		for _, port := range serviceTCPPorts {
			if port > 1024 {
				ports = append(ports, port)
			}
		}
		return ports, nil
	case TCPProfileFull:
		ports := make([]uint16, 65535)
		for index := range ports {
			ports[index] = uint16(index + 1)
		}
		return ports, nil
	default:
		return nil, fmt.Errorf("unknown TCP inspection profile %q", profile)
	}
}

type portJobQueue struct {
	addresses []netip.Addr
	ports     []uint16
	total     uint64
	next      atomic.Uint64
}

func newPortJobQueue(addresses []netip.Addr, ports []uint16) *portJobQueue {
	return &portJobQueue{
		addresses: addresses,
		ports:     ports,
		total:     uint64(len(addresses)) * uint64(len(ports)),
	}
}

// take walks addresses round-robin for each port. This avoids directing the
// whole worker pool at one host and gives multi-device inspections fair
// progress when the engine is reused for a batch.
func (jobs *portJobQueue) take() (probeJob, bool) {
	index := jobs.next.Add(1) - 1
	if index >= jobs.total || len(jobs.addresses) == 0 {
		return probeJob{}, false
	}
	addressIndex := index % uint64(len(jobs.addresses))
	portIndex := index / uint64(len(jobs.addresses))
	return probeJob{
		address: jobs.addresses[addressIndex],
		port:    jobs.ports[portIndex],
	}, true
}

func (jobs *portJobQueue) takeBatch(maximum int) []probeJob {
	batch := make([]probeJob, 0, maximum)
	for len(batch) < maximum {
		job, ok := jobs.take()
		if !ok {
			break
		}
		batch = append(batch, job)
	}
	return batch
}

type portScan struct {
	tcp        protocolPortScan
	tcpScanned bool
}

type protocolPortScan struct {
	open      map[netip.Addr][]uint16
	reachable map[netip.Addr]struct{}
}

func applyPortScan(foundByIP map[netip.Addr]devices.Device, scan portScan) {
	if !scan.tcpScanned {
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
	for address, item := range foundByIP {
		item.OpenPorts = append([]uint16{}, scan.tcp.open[address]...)
		foundByIP[address] = item
	}
}

// InspectTCP inspects one known device with the selected profile. Network
// discovery deliberately does not call this operation.
func (s *Scanner) InspectTCP(ctx context.Context, address netip.Addr, profile TCPProfile) (TCPInspection, error) {
	if !address.IsValid() || !address.Is4() {
		return TCPInspection{}, errors.New("TCP inspection requires an IPv4 address")
	}
	if err := s.validatePortInspectionConfig(); err != nil {
		return TCPInspection{}, err
	}
	ports, err := tcpPortsForProfile(profile)
	if err != nil {
		return TCPInspection{}, err
	}
	started := time.Now()
	scan, peak, err := s.scanTCPPorts(ctx, []netip.Addr{address}, ports)
	if err != nil {
		return TCPInspection{}, err
	}
	result := TCPInspection{
		OpenPorts:       append([]uint16(nil), scan.open[address]...),
		PortsProbed:     len(ports),
		PeakConcurrency: peak,
		Duration:        time.Since(started),
	}
	_, result.Reachable = scan.reachable[address]
	s.observeStage("tcp-inspection", started, len(ports))
	return result, nil
}

func (s *Scanner) validatePortInspectionConfig() error {
	if s.config.PortTimeout <= 0 {
		return errors.New("port probe timeout must be greater than zero")
	}
	if s.config.PortMinConcurrency < 1 {
		return errors.New("minimum port concurrency must be at least 1")
	}
	if s.config.PortMaxConcurrency < s.config.PortMinConcurrency {
		return errors.New("maximum port concurrency must not be below the minimum")
	}
	return nil
}

type inspectionProbeResult struct {
	address         netip.Addr
	port            uint16
	open            bool
	reachable       bool
	timedOut        bool
	resourceLimited bool
}

type inspectionBatchStats struct {
	total           int
	timedOut        int
	resourceLimited int
}

func (s *Scanner) scanTCPPorts(ctx context.Context, addresses []netip.Addr, ports []uint16) (protocolPortScan, int, error) {
	result := protocolPortScan{
		open:      make(map[netip.Addr][]uint16, len(addresses)),
		reachable: make(map[netip.Addr]struct{}, len(addresses)),
	}
	if len(addresses) == 0 || len(ports) == 0 {
		return result, 0, nil
	}

	queue := newPortJobQueue(addresses, ports)
	controller := newAdaptiveConcurrency(s.config.PortMinConcurrency, s.config.PortMaxConcurrency)
	peak := 0
	for {
		batch := queue.takeBatch(controller.current * 4)
		if len(batch) == 0 {
			break
		}
		workers := min(controller.current, len(batch))
		peak = max(peak, workers)
		outcomes, stats := s.runTCPInspectionBatch(ctx, batch, workers)
		for _, outcome := range outcomes {
			if outcome.reachable {
				result.reachable[outcome.address] = struct{}{}
			}
			if outcome.open {
				result.open[outcome.address] = append(result.open[outcome.address], outcome.port)
			}
		}
		if err := ctx.Err(); err != nil {
			return protocolPortScan{}, peak, err
		}
		controller.adjust(stats)
	}
	for address := range result.open {
		sort.Slice(result.open[address], func(left, right int) bool {
			return result.open[address][left] < result.open[address][right]
		})
	}
	return result, peak, nil
}

func (s *Scanner) runTCPInspectionBatch(ctx context.Context, jobs []probeJob, workers int) ([]inspectionProbeResult, inspectionBatchStats) {
	outcomes := make([]inspectionProbeResult, len(jobs))
	var next atomic.Uint64
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for {
				index := next.Add(1) - 1
				if index >= uint64(len(jobs)) || ctx.Err() != nil {
					return
				}
				job := jobs[index]
				outcomes[index] = s.inspectTCPPort(ctx, job.address, job.port)
			}
		}()
	}
	group.Wait()
	stats := inspectionBatchStats{total: len(outcomes)}
	for _, outcome := range outcomes {
		if outcome.timedOut {
			stats.timedOut++
		}
		if outcome.resourceLimited {
			stats.resourceLimited++
		}
	}
	return outcomes, stats
}

type adaptiveConcurrency struct {
	current              int
	minimum              int
	maximum              int
	previousTimeoutRatio float64
	hasPrevious          bool
	growthCooldown       int
}

func newAdaptiveConcurrency(minimum, maximum int) *adaptiveConcurrency {
	return &adaptiveConcurrency{current: minimum, minimum: minimum, maximum: maximum}
}

// adjust uses pressure signals around an aggressive ramp. Stable
// timeout rates usually mean remote filtering rather than local overload, so
// the pool keeps growing. A sharp timeout increase or a local socket-resource
// error cuts concurrency immediately.
func (controller *adaptiveConcurrency) adjust(stats inspectionBatchStats) {
	if stats.total == 0 {
		return
	}
	ratio := float64(stats.timedOut) / float64(stats.total)
	congested := stats.resourceLimited > 0 ||
		(controller.hasPrevious && ratio > controller.previousTimeoutRatio+0.15)
	if congested {
		controller.current = max(controller.minimum, controller.current/2)
		controller.growthCooldown = 2
	} else if controller.growthCooldown > 0 {
		controller.growthCooldown--
	} else if controller.current < controller.maximum {
		controller.current = min(controller.maximum, controller.current*2)
	}
	controller.previousTimeoutRatio = ratio
	controller.hasPrevious = true
}

func isLocalResourceError(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOMEM)
}
