package fleet

import (
	"errors"
	"net/netip"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

// PortInspectionProfile selects the amount of explicit TCP inspection work.
type PortInspectionProfile string

const (
	// PortInspectionServices checks a small fleet-oriented service set.
	PortInspectionServices PortInspectionProfile = "services"
	// PortInspectionCommon checks ports 1-1024 plus fleet-oriented services.
	PortInspectionCommon PortInspectionProfile = "common"
	// PortInspectionFullTCP checks every usable TCP port and is deliberately
	// explicit because it can still take a long time against a filtering host.
	PortInspectionFullTCP PortInspectionProfile = "full-tcp"
)

// ErrDeviceNotFound is returned when an inspection target is not in inventory.
var ErrDeviceNotFound = errors.New("device not found")

// InvalidPortInspectionError reports an invalid inspection request.
type InvalidPortInspectionError struct {
	Reason string
}

func (e *InvalidPortInspectionError) Error() string {
	return e.Reason
}

// PortInspectionRequest identifies an inventoried device and inspection
// profile. Refresh bypasses a completed cache entry but still coalesces with an
// identical inspection already in progress.
type PortInspectionRequest struct {
	DeviceID devices.ID
	Profile  PortInspectionProfile
	Refresh  bool
}

// PortInspectionResult contains one targeted TCP inspection.
type PortInspectionResult struct {
	DeviceID        devices.ID
	IP              netip.Addr
	Profile         PortInspectionProfile
	OpenPorts       []uint16
	Reachable       bool
	PortsProbed     int
	PeakConcurrency int
	InspectedAt     time.Time
	Duration        time.Duration
	Cached          bool
}
