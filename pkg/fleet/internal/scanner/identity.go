package scanner

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

// Identity is a name learned through a local discovery protocol.
type Identity struct {
	IP       netip.Addr
	Name     string
	Hostname string
	Method   string
}

// IdentitySource discovers identities advertised on the local network. Add an
// implementation to Config.IdentitySources to extend discovery.
type IdentitySource interface {
	Discover(context.Context, netip.Prefix) ([]Identity, error)
}

type identityResult struct {
	index      int
	identities []Identity
}

func (s *Scanner) startIdentitySources(ctx context.Context, prefix netip.Prefix) <-chan identityResult {
	results := make(chan identityResult, len(s.identities))
	if !s.config.ResolveNames {
		close(results)
		return results
	}
	var workers sync.WaitGroup
	workers.Add(len(s.identities))
	for index, source := range s.identities {
		go func() {
			defer workers.Done()
			identities, err := source.Discover(ctx, prefix)
			if err != nil {
				return
			}
			select {
			case results <- identityResult{index: index, identities: identities}:
			case <-ctx.Done():
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()
	return results
}

func collectIdentities(results <-chan identityResult, count int) []identityResult {
	batches := make([]identityResult, count)
	for result := range results {
		batches[result.index] = result
	}
	return batches
}

func applyIdentities(foundByIP map[netip.Addr]devices.Device, prefix netip.Prefix, count uint64, batches []identityResult) {
	for _, batch := range batches {
		for _, identity := range batch.identities {
			if (identity.Name == "" && identity.Hostname == "") || !prefix.Contains(identity.IP) || isReservedAddress(prefix, count, identity.IP) {
				continue
			}
			item := foundByIP[identity.IP]
			if !item.IP.IsValid() {
				now := time.Now().UTC()
				item = devices.Device{IP: identity.IP, OpenPorts: []uint16{}, FirstSeen: now, LastSeen: now}
			}
			if item.Name == "" {
				item.Name = identity.Name
			}
			if item.Hostname == "" {
				item.Hostname = identity.Hostname
			}
			item.AddDiscovery(identity.Method)
			foundByIP[identity.IP] = item
		}
	}
}

func (s *Scanner) resolveHostnames(ctx context.Context, foundByIP map[netip.Addr]devices.Device) error {
	addresses := make([]netip.Addr, 0, len(foundByIP))
	for address, item := range foundByIP {
		if item.Hostname == "" {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil
	}
	jobs := make(chan netip.Addr)
	type result struct {
		address  netip.Addr
		hostname string
	}
	results := make(chan result)
	workerCount := min(s.config.Concurrency, len(addresses))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for address := range jobs {
				lookupContext, cancel := context.WithTimeout(ctx, s.config.Timeout)
				names, err := net.DefaultResolver.LookupAddr(lookupContext, address.String())
				cancel()
				hostname := ""
				if err == nil && len(names) > 0 {
					hostname = strings.TrimSuffix(names[0], ".")
				}
				select {
				case results <- result{address: address, hostname: hostname}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, address := range addresses {
			select {
			case jobs <- address:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	for resolved := range results {
		if resolved.hostname == "" {
			continue
		}
		item := foundByIP[resolved.address]
		if item.Hostname == "" {
			item.Hostname = resolved.hostname
			foundByIP[resolved.address] = item
		}
	}
	return ctx.Err()
}

func finalizeDeviceNames(foundByIP map[netip.Addr]devices.Device) {
	for address, item := range foundByIP {
		if item.Name == "" && item.Hostname != "" {
			candidate := strings.TrimSuffix(item.Hostname, ".local")
			if !looksLikeUUID(candidate) && !looksOpaqueIdentifier(candidate) {
				item.Name = candidate
			}
		}
		foundByIP[address] = item
	}
}

func looksOpaqueIdentifier(value string) bool {
	if len(value) < 12 || strings.ContainsAny(value, " _-") {
		return false
	}
	var lower, upper, digit bool
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
			lower = true
		case character >= 'A' && character <= 'Z':
			upper = true
		case character >= '0' && character <= '9':
			digit = true
		}
	}
	return lower && upper && digit
}

func looksLikeUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}
