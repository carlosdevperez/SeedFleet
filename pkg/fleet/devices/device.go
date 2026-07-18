// Package devices defines the device information retained by a fleet Provider.
package devices

import (
	"net/netip"
	"sort"
	"time"
)

// ID identifies a device independently from its current network address.
type ID string

// Device is the information learned about one device on the network.
type Device struct {
	ID           ID
	IP           netip.Addr
	MAC          string
	Name         string
	Manufacturer string
	Hostname     string
	// OpenPorts contains open TCP ports. It retains its original name for
	// compatibility with existing Provider consumers and HTTP representations.
	OpenPorts []uint16
	// OpenUDPPorts contains UDP ports that replied to a probe. Silent UDP ports
	// are ambiguous and are not included.
	OpenUDPPorts []uint16
	DiscoveredBy []string
	FirstSeen    time.Time
	LastSeen     time.Time
}

// Refresh combines a new scan result with historical inventory identity. Open
// TCP and UDP ports represent the new scan, while stable identity and discovery
// history are preserved when the new observation cannot provide them.
func Refresh(existing, current Device) Device {
	if !existing.IP.IsValid() {
		return current
	}
	current.ID = existing.ID
	if !existing.FirstSeen.IsZero() {
		current.FirstSeen = existing.FirstSeen
	}
	if existing.LastSeen.After(current.LastSeen) {
		current.LastSeen = existing.LastSeen
	}
	if current.MAC == "" {
		current.MAC = existing.MAC
	}
	if current.Name == "" {
		current.Name = existing.Name
	}
	if current.Manufacturer == "" {
		current.Manufacturer = existing.Manufacturer
	}
	if current.Hostname == "" {
		current.Hostname = existing.Hostname
	}
	current.DiscoveredBy = mergeStrings(existing.DiscoveredBy, current.DiscoveredBy)
	return current
}

// Combine merges independent observations made during the same scan.
func Combine(existing, found Device) Device {
	if !existing.IP.IsValid() {
		return found
	}
	if found.ID == "" {
		found.ID = existing.ID
	}
	if found.MAC == "" {
		found.MAC = existing.MAC
	}
	if found.Name == "" {
		found.Name = existing.Name
	}
	if found.Manufacturer == "" {
		found.Manufacturer = existing.Manufacturer
	}
	if found.Hostname == "" {
		found.Hostname = existing.Hostname
	}
	found.OpenPorts = mergePorts(existing.OpenPorts, found.OpenPorts)
	found.OpenUDPPorts = mergePorts(existing.OpenUDPPorts, found.OpenUDPPorts)
	found.DiscoveredBy = mergeStrings(existing.DiscoveredBy, found.DiscoveredBy)
	if found.FirstSeen.IsZero() || (!existing.FirstSeen.IsZero() && existing.FirstSeen.Before(found.FirstSeen)) {
		found.FirstSeen = existing.FirstSeen
	}
	if existing.LastSeen.After(found.LastSeen) {
		found.LastSeen = existing.LastSeen
	}
	return found
}

// AddDiscovery records a discovery method once.
func (d *Device) AddDiscovery(method string) {
	if method != "" {
		d.DiscoveredBy = mergeStrings(d.DiscoveredBy, []string{method})
	}
}

func mergePorts(left, right []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(left)+len(right))
	result := make([]uint16, 0, len(left)+len(right))
	for _, ports := range [][]uint16{left, right} {
		for _, port := range ports {
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			result = append(result, port)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func mergeStrings(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	result := make([]string, 0, len(left)+len(right))
	for _, values := range [][]string{left, right} {
		for _, value := range values {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}
