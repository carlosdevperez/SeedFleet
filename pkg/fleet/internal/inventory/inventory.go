// Package inventory provides SeedFleet's process-local device store.
package inventory

import (
	"context"
	"net/netip"
	"sort"
	"sync"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

// Inventory is an in-memory repository safe for concurrent use.
type Inventory struct {
	mu       sync.RWMutex
	devices  map[netip.Addr]devices.Device
	snapshot []devices.Device
}

// New returns an empty inventory.
func New() *Inventory {
	return &Inventory{devices: make(map[netip.Addr]devices.Device)}
}

// Save commits a scan result under one lock and returns independent
// copies in the same order as the input.
func (i *Inventory) Save(ctx context.Context, found []devices.Device) ([]devices.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	result := make([]devices.Device, len(found))
	for index, item := range found {
		result[index] = i.upsertLocked(item)
	}
	i.rebuildSnapshotLocked()
	return result, nil
}

func (i *Inventory) upsertLocked(found devices.Device) devices.Device {
	if existing, ok := i.devices[found.IP]; ok {
		found = devices.Refresh(existing, found)
	}
	found.OpenPorts = clonePorts(found.OpenPorts)
	found.OpenUDPPorts = clonePorts(found.OpenUDPPorts)
	found.DiscoveredBy = append([]string(nil), found.DiscoveredBy...)
	i.devices[found.IP] = found
	return clone(found)
}

// List returns a stable snapshot sorted by IP address.
func (i *Inventory) List(ctx context.Context) ([]devices.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	i.mu.RLock()
	result := make([]devices.Device, len(i.snapshot))
	for index, item := range i.snapshot {
		result[index] = clone(item)
	}
	i.mu.RUnlock()
	return result, nil
}

func (i *Inventory) rebuildSnapshotLocked() {
	i.snapshot = make([]devices.Device, 0, len(i.devices))
	for _, item := range i.devices {
		i.snapshot = append(i.snapshot, item)
	}
	sort.Slice(i.snapshot, func(left, right int) bool {
		return i.snapshot[left].IP.Compare(i.snapshot[right].IP) < 0
	})
}

func clone(item devices.Device) devices.Device {
	item.OpenPorts = clonePorts(item.OpenPorts)
	item.OpenUDPPorts = clonePorts(item.OpenUDPPorts)
	item.DiscoveredBy = append([]string(nil), item.DiscoveredBy...)
	return item
}

func clonePorts(ports []uint16) []uint16 {
	result := make([]uint16, len(ports))
	copy(result, ports)
	return result
}
