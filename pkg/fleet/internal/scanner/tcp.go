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
	"time"
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
// primary purpose is to prime the operating-system neighbor cache before the
// complete port sweep can outlive those cache entries.
func (s *Scanner) scanTCPDiscovery(ctx context.Context, addresses []netip.Addr) (protocolPortScan, error) {
	discovery := protocolPortScan{
		open:      make(map[netip.Addr][]uint16, len(addresses)),
		reachable: make(map[netip.Addr]struct{}, len(addresses)),
	}
	if len(addresses) == 0 || len(s.config.DiscoveryPorts) == 0 {
		return discovery, nil
	}

	workerCount := s.config.ProbeConcurrency
	if workerCount < 1 {
		workerCount = s.config.Concurrency * len(s.config.DiscoveryPorts)
	}
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
				open, reachable := s.probePort(ctx, job.address, job.port, s.config.Timeout)
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

func (s *Scanner) scanTCPPorts(ctx context.Context, addresses []netip.Addr) (protocolPortScan, error) {
	portScan := protocolPortScan{
		open:      make(map[netip.Addr][]uint16, len(addresses)),
		reachable: make(map[netip.Addr]struct{}, len(addresses)),
	}
	if len(addresses) == 0 || !s.config.TCPPortRange.enabled() {
		return portScan, nil
	}

	workerCount := boundedWorkerCount(s.config.ProbeConcurrency, len(addresses), s.config.TCPPortRange)
	jobs := newPortJobQueue(addresses, s.config.TCPPortRange)
	results := make(chan probeResult, workerCount)
	var reported sync.Map
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				job, ok := jobs.take()
				if !ok {
					return
				}
				open, reachable := s.probePort(ctx, job.address, job.port, s.config.PortTimeout)
				if !reachable {
					continue
				}
				_, alreadyReported := reported.LoadOrStore(job.address, struct{}{})
				if !open && alreadyReported {
					continue
				}
				select {
				case results <- probeResult{address: job.address, port: job.port, open: open, reachable: !alreadyReported}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	for result := range results {
		if result.reachable {
			portScan.reachable[result.address] = struct{}{}
		}
		if result.open {
			portScan.open[result.address] = append(portScan.open[result.address], result.port)
		}
	}
	if err := ctx.Err(); err != nil {
		return protocolPortScan{}, err
	}
	for address := range portScan.open {
		sort.Slice(portScan.open[address], func(i, j int) bool { return portScan.open[address][i] < portScan.open[address][j] })
	}
	return portScan, nil
}

func (s *Scanner) probePort(ctx context.Context, address netip.Addr, port uint16, timeout time.Duration) (open, reachable bool) {
	endpoint := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
	var connection net.Conn
	var err error
	if s.config.DialContext != nil {
		connection, err = s.config.DialContext(ctx, "tcp", endpoint)
	} else {
		dialer := net.Dialer{Timeout: timeout}
		connection, err = dialer.DialContext(ctx, "tcp", endpoint)
	}
	if err == nil {
		_ = connection.Close()
		return true, true
	}
	return false, errors.Is(err, syscall.ECONNREFUSED)
}
