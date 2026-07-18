package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
)

type probeJob struct {
	address netip.Addr
	port    uint16
}

type probeResult struct {
	address   netip.Addr
	port      uint16
	open      bool
	reachable bool
}

// scanTCPDiscovery performs a short pass over a small set of TCP ports. Its
// primary purpose is host discovery and priming the operating-system neighbor
// cache for quiet devices that do not accept a configured connection.
func (s *Scanner) scanTCPDiscovery(ctx context.Context, addresses []netip.Addr) (protocolPortScan, error) {
	discovery := protocolPortScan{
		open:      make(map[netip.Addr][]uint16, len(addresses)),
		reachable: make(map[netip.Addr]struct{}, len(addresses)),
	}
	if len(addresses) == 0 || len(s.config.DiscoveryPorts) == 0 {
		return discovery, nil
	}

	workerCount := s.config.DiscoveryConcurrency
	jobCount := len(addresses) * len(s.config.DiscoveryPorts)
	if workerCount > jobCount {
		workerCount = jobCount
	}

	jobs := make(chan probeJob)
	results := make(chan probeResult, workerCount)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				open, reachable := s.probeDiscoveryPort(ctx, job.address, job.port)
				if !reachable {
					continue
				}
				select {
				case results <- probeResult{address: job.address, port: job.port, open: open, reachable: true}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, address := range addresses {
			for _, port := range s.config.DiscoveryPorts {
				select {
				case jobs <- probeJob{address: address, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	for result := range results {
		discovery.reachable[result.address] = struct{}{}
		if result.open {
			discovery.open[result.address] = append(discovery.open[result.address], result.port)
		}
	}
	if err := ctx.Err(); err != nil {
		return protocolPortScan{}, err
	}
	for address := range discovery.open {
		sort.Slice(discovery.open[address], func(i, j int) bool {
			return discovery.open[address][i] < discovery.open[address][j]
		})
	}
	return discovery, nil
}

func (s *Scanner) probeDiscoveryPort(ctx context.Context, address netip.Addr, port uint16) (open, reachable bool) {
	endpoint := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
	connection, err := s.discoveryDial(ctx, "tcp", endpoint)
	if err == nil {
		_ = connection.Close()
		return true, true
	}
	return false, errors.Is(err, syscall.ECONNREFUSED)
}

func (s *Scanner) inspectTCPPort(ctx context.Context, address netip.Addr, port uint16) inspectionProbeResult {
	result := inspectionProbeResult{address: address, port: port}
	endpoint := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
	connection, err := s.inspectionDial(ctx, "tcp", endpoint)
	if err == nil {
		_ = connection.Close()
		result.open = true
		result.reachable = true
		return result
	}
	result.reachable = errors.Is(err, syscall.ECONNREFUSED)
	var networkError net.Error
	result.timedOut = errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &networkError) && networkError.Timeout())
	result.resourceLimited = isLocalResourceError(err)
	return result
}
