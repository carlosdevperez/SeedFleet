package inventory

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

func TestInventorySavePreservesIdentityAndFirstSeen(t *testing.T) {
	inventory := New()
	ip := netip.MustParseAddr("192.0.2.10")
	first := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	later := first.Add(time.Minute)

	_, err := inventory.Save(context.Background(), []devices.Device{{
		IP: ip, MAC: "aa:bb:cc:dd:ee:ff", Name: "Office printer", Manufacturer: "Example Corp",
		Hostname: "printer.local", OpenPorts: []uint16{80}, DiscoveredBy: []string{"tcp"},
		FirstSeen: first, LastSeen: first,
	}})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := inventory.Save(context.Background(), []devices.Device{{
		IP: ip, OpenPorts: []uint16{443}, DiscoveredBy: []string{"neighbor"}, FirstSeen: later, LastSeen: later,
	}})
	if err != nil {
		t.Fatal(err)
	}
	item := updated[0]
	if item.FirstSeen != first || item.LastSeen != later {
		t.Fatalf("timestamps = %v/%v, want %v/%v", item.FirstSeen, item.LastSeen, first, later)
	}
	if item.MAC != "aa:bb:cc:dd:ee:ff" || item.Name != "Office printer" || item.Manufacturer != "Example Corp" || item.Hostname != "printer.local" {
		t.Fatalf("identity was not preserved: %#v", item)
	}
	if len(item.OpenPorts) != 1 || item.OpenPorts[0] != 443 {
		t.Fatalf("OpenPorts = %v, want [443]", item.OpenPorts)
	}
	if got := item.DiscoveredBy; len(got) != 2 || got[0] != "tcp" || got[1] != "neighbor" {
		t.Fatalf("DiscoveredBy = %v, want [tcp neighbor]", got)
	}
}

func TestInventoryListSortsAndReturnsCopies(t *testing.T) {
	inventory := New()
	now := time.Now()
	_, err := inventory.Save(context.Background(), []devices.Device{
		{IP: netip.MustParseAddr("192.0.2.20"), OpenPorts: []uint16{80}, FirstSeen: now, LastSeen: now},
		{IP: netip.MustParseAddr("192.0.2.3"), OpenPorts: []uint16{22}, FirstSeen: now, LastSeen: now},
	})
	if err != nil {
		t.Fatal(err)
	}

	items, err := inventory.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := items[0].IP.String(); got != "192.0.2.3" {
		t.Fatalf("first IP = %s, want 192.0.2.3", got)
	}
	items[0].OpenPorts[0] = 9999
	stored, err := inventory.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stored[0].OpenPorts[0] != 22 {
		t.Fatalf("stored port changed through returned slice: %d", stored[0].OpenPorts[0])
	}
}

func TestInventorySavePreservesInputOrderAndReturnsCopies(t *testing.T) {
	inventory := New()
	now := time.Now()
	result, err := inventory.Save(context.Background(), []devices.Device{
		{IP: netip.MustParseAddr("192.0.2.2"), Name: "second", OpenPorts: []uint16{80}, FirstSeen: now, LastSeen: now},
		{IP: netip.MustParseAddr("192.0.2.1"), Name: "first", OpenPorts: []uint16{}, FirstSeen: now, LastSeen: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result[0].Name != "second" || result[1].Name != "first" {
		t.Fatalf("batch result order changed: %#v", result)
	}
	result[0].OpenPorts[0] = 9999
	stored, err := inventory.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stored[1].OpenPorts[0] != 80 {
		t.Fatalf("stored port changed through save result: %d", stored[1].OpenPorts[0])
	}
}
