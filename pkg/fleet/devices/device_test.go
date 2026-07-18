package devices

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestRefreshPreservesHistoricalIdentityAndUsesCurrentPorts(t *testing.T) {
	first := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	later := first.Add(time.Minute)
	address := netip.MustParseAddr("192.0.2.1")
	id := ID("dev_test")
	refreshed := Refresh(
		Device{ID: id, IP: address, MAC: "aa:bb:cc:dd:ee:ff", Name: "Router", Manufacturer: "Example", Hostname: "router.local", OpenPorts: []uint16{80}, DiscoveredBy: []string{"tcp"}, FirstSeen: first, LastSeen: first},
		Device{IP: address, OpenPorts: []uint16{443}, DiscoveredBy: []string{"neighbor"}, FirstSeen: later, LastSeen: later},
	)
	if refreshed.ID != id || refreshed.FirstSeen != first || refreshed.LastSeen != later || refreshed.Name != "Router" || refreshed.MAC == "" || refreshed.Manufacturer == "" || refreshed.Hostname == "" {
		t.Fatalf("refreshed identity = %#v", refreshed)
	}
	if !reflect.DeepEqual(refreshed.OpenPorts, []uint16{443}) || !reflect.DeepEqual(refreshed.DiscoveredBy, []string{"tcp", "neighbor"}) {
		t.Fatalf("refreshed observations = %#v", refreshed)
	}
}

func TestCombineMergesSameScanObservations(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.1")
	now := time.Now()
	combined := Combine(
		Device{IP: address, OpenPorts: []uint16{443, 80}, DiscoveredBy: []string{"tcp"}, FirstSeen: now},
		Device{IP: address, Name: "Router", OpenPorts: []uint16{22, 80}, DiscoveredBy: []string{"neighbor"}, LastSeen: now.Add(time.Second)},
	)
	if !reflect.DeepEqual(combined.OpenPorts, []uint16{22, 80, 443}) || !reflect.DeepEqual(combined.DiscoveredBy, []string{"tcp", "neighbor"}) {
		t.Fatalf("combined = %#v", combined)
	}
	if combined.Name != "Router" || combined.FirstSeen != now {
		t.Fatalf("combined identity/timestamps = %#v", combined)
	}
}
