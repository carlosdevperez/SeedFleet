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

func (s *Scanner) scanUDPPorts(ctx context.Context, addresses []netip.Addr) (protocolPortScan, error) {
	portScan := protocolPortScan{
		open:      make(map[netip.Addr][]uint16, len(addresses)),
		reachable: make(map[netip.Addr]struct{}, len(addresses)),
	}
	if len(addresses) == 0 || !s.config.UDPPortRange.enabled() {
		return portScan, nil
	}

	workerCount := boundedWorkerCount(s.config.ProbeConcurrency, len(addresses), s.config.UDPPortRange)
	jobs := newPortJobQueue(addresses, s.config.UDPPortRange)
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
				open, reachable := s.probeUDPPort(ctx, job.address, job.port)
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

// probeUDPPort sends an empty UDP datagram and reports the port as open only
// when the endpoint replies. A timeout is not considered open because UDP
// cannot distinguish a silent service from a firewall that dropped the probe.
func (s *Scanner) probeUDPPort(ctx context.Context, address netip.Addr, port uint16) (open, reachable bool) {
	endpoint := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
	var connection net.Conn
	var err error
	if s.config.DialContext != nil {
		connection, err = s.config.DialContext(ctx, "udp4", endpoint)
	} else {
		dialer := net.Dialer{Timeout: s.config.PortTimeout}
		connection, err = dialer.DialContext(ctx, "udp4", endpoint)
	}
	if err != nil {
		return false, udpHostReachable(err)
	}
	defer connection.Close()

	deadline := time.Now().Add(s.config.PortTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return false, false
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopCancellation()

	if _, err := connection.Write(nil); err != nil {
		return false, udpHostReachable(err)
	}
	var response [2048]byte
	_, err = connection.Read(response[:])
	if err == nil {
		return true, true
	}
	return false, udpHostReachable(err)
}

func udpHostReachable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}
