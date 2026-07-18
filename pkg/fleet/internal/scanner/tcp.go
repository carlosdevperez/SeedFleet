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

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

type probeJob struct {
	address netip.Addr
	port    uint16
}

type probeResult struct {
	address netip.Addr
	port    uint16
	open    bool
}

func (s *Scanner) scanTCP(ctx context.Context, prefix netip.Prefix, count uint64) (map[netip.Addr]devices.Device, error) {
	jobs := make(chan probeJob)
	results := make(chan probeResult)
	workerCount := s.config.ProbeConcurrency
	if workerCount < 1 {
		workerCount = s.config.Concurrency * len(s.config.Ports)
	}
	maximumJobs := usableAddressCount(prefix, count) * uint64(len(s.config.Ports))
	if uint64(workerCount) > maximumJobs {
		workerCount = int(maximumJobs)
	}

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				open, reachable := s.probePort(ctx, job.address, job.port)
				if !reachable {
					continue
				}
				select {
				case results <- probeResult{address: job.address, port: job.port, open: open}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		forEachUsableAddress(prefix, count, func(address netip.Addr) bool {
			for _, port := range s.config.Ports {
				select {
				case jobs <- probeJob{address: address, port: port}:
				case <-ctx.Done():
					return false
				}
			}
			return true
		})
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	foundByIP := make(map[netip.Addr]devices.Device)
	for result := range results {
		item := foundByIP[result.address]
		if !item.IP.IsValid() {
			now := time.Now().UTC()
			item = devices.Device{
				IP:           result.address,
				OpenPorts:    []uint16{},
				DiscoveredBy: []string{"tcp"},
				FirstSeen:    now,
				LastSeen:     now,
			}
		}
		if result.open {
			item.OpenPorts = append(item.OpenPorts, result.port)
		}
		foundByIP[result.address] = item
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for address, item := range foundByIP {
		sort.Slice(item.OpenPorts, func(i, j int) bool { return item.OpenPorts[i] < item.OpenPorts[j] })
		foundByIP[address] = item
	}
	return foundByIP, nil
}

func (s *Scanner) probePort(ctx context.Context, address netip.Addr, port uint16) (open, reachable bool) {
	endpoint := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
	var connection net.Conn
	var err error
	if s.config.DialContext != nil {
		connection, err = s.config.DialContext(ctx, "tcp", endpoint)
	} else {
		dialer := net.Dialer{Timeout: s.config.Timeout}
		connection, err = dialer.DialContext(ctx, "tcp", endpoint)
	}
	if err == nil {
		_ = connection.Close()
		return true, true
	}
	return false, errors.Is(err, syscall.ECONNREFUSED)
}
