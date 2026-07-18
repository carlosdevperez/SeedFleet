package scanner

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

// Neighbor is a complete IPv4-to-MAC mapping learned by the operating system.
type Neighbor struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

// NeighborSource supplies layer-2 observations. It is deliberately small so a
// native Windows implementation can be used when the service runs on Windows.
type NeighborSource interface {
	List(context.Context) ([]Neighbor, error)
}

func (s *Scanner) scanNeighbors(ctx context.Context, prefix netip.Prefix, count uint64, foundByIP map[netip.Addr]devices.Device) error {
	neighbors, err := s.neighbors.List(ctx)
	if err != nil {
		return ctx.Err()
	}
	for _, neighbor := range neighbors {
		if !prefix.Contains(neighbor.IP) || isReservedAddress(prefix, count, neighbor.IP) {
			continue
		}
		now := time.Now().UTC()
		item := devices.Device{
			IP:           neighbor.IP,
			MAC:          neighbor.MAC.String(),
			OpenPorts:    []uint16{},
			OpenUDPPorts: []uint16{},
			DiscoveredBy: []string{"neighbor"},
			FirstSeen:    now,
			LastSeen:     now,
		}
		if alias, ok := aliasForMAC(s.config.Aliases, item.MAC); ok {
			item.Name = alias.Name
			item.Hostname = alias.Hostname
			item.Manufacturer = alias.Manufacturer
			item.DiscoveredBy = append(item.DiscoveredBy, "alias")
		}
		foundByIP[item.IP] = devices.Combine(foundByIP[item.IP], item)
	}
	return ctx.Err()
}
