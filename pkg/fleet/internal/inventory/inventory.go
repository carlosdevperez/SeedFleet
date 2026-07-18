// Package inventory provides SeedFleet's interchangeable device stores.
package inventory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

// Memory is an in-memory repository safe for concurrent use.
type Memory struct {
	mu       sync.RWMutex
	devices  map[devices.ID]devices.Device
	byIP     map[netip.Addr]devices.ID
	byMAC    map[string]devices.ID
	snapshot []devices.Device
}

// NewMemory returns an empty in-memory inventory.
func NewMemory() *Memory {
	return &Memory{
		devices: make(map[devices.ID]devices.Device),
		byIP:    make(map[netip.Addr]devices.ID),
		byMAC:   make(map[string]devices.ID),
	}
}

// Save commits a scan result under one lock and returns independent
// copies in the same order as the input.
func (i *Memory) Save(ctx context.Context, found []devices.Device) ([]devices.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateDevices(found); err != nil {
		return nil, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]devices.Device, len(found))
	for index, item := range found {
		stored, err := i.upsertLocked(item)
		if err != nil {
			return nil, err
		}
		result[index] = stored
	}
	i.rebuildSnapshotLocked()
	return result, nil
}

func (i *Memory) upsertLocked(found devices.Device) (devices.Device, error) {
	id, existing, ok := i.matchLocked(found)
	if ok {
		found = devices.Refresh(existing, found)
	} else {
		id = found.ID
		if id == "" {
			var err error
			for id == "" {
				candidate, candidateErr := newDeviceID()
				if candidateErr != nil {
					err = candidateErr
					break
				}
				if _, exists := i.devices[candidate]; !exists {
					id = candidate
				}
			}
			if err != nil {
				return devices.Device{}, fmt.Errorf("create device identity: %w", err)
			}
		}
		found.ID = id
	}

	// A current observation owns its address. If another durable device used
	// that address previously, discard that stale address record.
	if occupant, exists := i.byIP[found.IP]; exists && occupant != id {
		i.deleteLocked(occupant)
	}
	if key := macKey(found.MAC); key != "" {
		if occupant, exists := i.byMAC[key]; exists && occupant != id {
			i.deleteLocked(occupant)
		}
	}
	if ok {
		i.deleteIndexesLocked(existing)
	}
	found.OpenPorts = clonePorts(found.OpenPorts)
	found.DiscoveredBy = append([]string(nil), found.DiscoveredBy...)
	i.devices[id] = found
	i.byIP[found.IP] = id
	if key := macKey(found.MAC); key != "" {
		i.byMAC[key] = id
	}
	return clone(found), nil
}

func (i *Memory) matchLocked(found devices.Device) (devices.ID, devices.Device, bool) {
	if found.ID != "" {
		if existing, ok := i.devices[found.ID]; ok {
			return found.ID, existing, true
		}
	}
	key := macKey(found.MAC)
	if id, ok := i.byMAC[key]; ok && key != "" {
		return id, i.devices[id], true
	}
	if id, ok := i.byIP[found.IP]; ok {
		existing := i.devices[id]
		existingKey := macKey(existing.MAC)
		if key == "" || existingKey == "" || key == existingKey {
			return id, existing, true
		}
	}
	return "", devices.Device{}, false
}

func (i *Memory) deleteLocked(id devices.ID) {
	item, ok := i.devices[id]
	if !ok {
		return
	}
	i.deleteIndexesLocked(item)
	delete(i.devices, id)
}

func (i *Memory) deleteIndexesLocked(item devices.Device) {
	if i.byIP[item.IP] == item.ID {
		delete(i.byIP, item.IP)
	}
	if key := macKey(item.MAC); key != "" && i.byMAC[key] == item.ID {
		delete(i.byMAC, key)
	}
}

// List returns a stable snapshot sorted by IP address.
func (i *Memory) List(ctx context.Context) ([]devices.Device, error) {
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

// Close releases inventory resources. Memory has no resources to release.
func (i *Memory) Close() error {
	return nil
}

func (i *Memory) rebuildSnapshotLocked() {
	i.snapshot = make([]devices.Device, 0, len(i.devices))
	for _, item := range i.devices {
		i.snapshot = append(i.snapshot, item)
	}
	sort.Slice(i.snapshot, func(left, right int) bool {
		return i.snapshot[left].IP.Compare(i.snapshot[right].IP) < 0
	})
}

func newDeviceID() (devices.ID, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return devices.ID("dev_" + hex.EncodeToString(value[:])), nil
}

func macKey(raw string) string {
	mac, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil || len(mac) != 6 {
		return ""
	}
	return mac.String()
}

func validateDevices(items []devices.Device) error {
	for index, item := range items {
		if !item.IP.IsValid() {
			return fmt.Errorf("device %d has an invalid IP address", index)
		}
	}
	return nil
}

func clone(item devices.Device) devices.Device {
	item.OpenPorts = clonePorts(item.OpenPorts)
	item.DiscoveredBy = append([]string(nil), item.DiscoveredBy...)
	return item
}

func clonePorts(ports []uint16) []uint16 {
	result := make([]uint16, len(ports))
	copy(result, ports)
	return result
}
