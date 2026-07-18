package inventory

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

type testInventory interface {
	Save(context.Context, []devices.Device) ([]devices.Device, error)
	List(context.Context) ([]devices.Device, error)
	Close() error
}

func testInventories(t *testing.T, test func(*testing.T, testInventory)) {
	t.Helper()
	implementations := []struct {
		name string
		new  func(*testing.T) testInventory
	}{
		{
			name: "memory",
			new: func(*testing.T) testInventory {
				return NewMemory()
			},
		},
		{
			name: "sqlite",
			new: func(t *testing.T) testInventory {
				inventory, err := NewSQLite(filepath.Join(t.TempDir(), "inventory.db"))
				if err != nil {
					t.Fatal(err)
				}
				return inventory
			},
		},
	}
	for _, implementation := range implementations {
		t.Run(implementation.name, func(t *testing.T) {
			inventory := implementation.new(t)
			t.Cleanup(func() {
				if err := inventory.Close(); err != nil {
					t.Errorf("close inventory: %v", err)
				}
			})
			test(t, inventory)
		})
	}
}

func TestInventorySavePreservesIdentityAndFirstSeen(t *testing.T) {
	testInventories(t, func(t *testing.T, inventory testInventory) {
		ip := netip.MustParseAddr("192.0.2.10")
		first := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
		later := first.Add(time.Minute)

		created, err := inventory.Save(context.Background(), []devices.Device{{
			IP: ip, MAC: "aa:bb:cc:dd:ee:ff", Name: "Office printer", Manufacturer: "Example Corp",
			Hostname: "printer.local", OpenPorts: []uint16{80}, OpenUDPPorts: []uint16{161}, DiscoveredBy: []string{"tcp", "udp"},
			FirstSeen: first, LastSeen: first,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if created[0].ID == "" {
			t.Fatal("saved device has an empty durable ID")
		}
		updated, err := inventory.Save(context.Background(), []devices.Device{{
			IP: ip, OpenPorts: []uint16{443}, OpenUDPPorts: []uint16{5353}, DiscoveredBy: []string{"neighbor"}, FirstSeen: later, LastSeen: later,
		}})
		if err != nil {
			t.Fatal(err)
		}
		item := updated[0]
		if item.ID != created[0].ID {
			t.Fatalf("ID = %q, want %q", item.ID, created[0].ID)
		}
		if item.FirstSeen != first || item.LastSeen != later {
			t.Fatalf("timestamps = %v/%v, want %v/%v", item.FirstSeen, item.LastSeen, first, later)
		}
		if item.MAC != "aa:bb:cc:dd:ee:ff" || item.Name != "Office printer" || item.Manufacturer != "Example Corp" || item.Hostname != "printer.local" {
			t.Fatalf("identity was not preserved: %#v", item)
		}
		if len(item.OpenPorts) != 1 || item.OpenPorts[0] != 443 {
			t.Fatalf("OpenPorts = %v, want [443]", item.OpenPorts)
		}
		if len(item.OpenUDPPorts) != 1 || item.OpenUDPPorts[0] != 5353 {
			t.Fatalf("OpenUDPPorts = %v, want [5353]", item.OpenUDPPorts)
		}
		if got := item.DiscoveredBy; len(got) != 3 || got[0] != "tcp" || got[1] != "udp" || got[2] != "neighbor" {
			t.Fatalf("DiscoveredBy = %v, want [tcp udp neighbor]", got)
		}
	})
}

func TestInventoryRetainsDeviceAcrossAddressChanges(t *testing.T) {
	testInventories(t, func(t *testing.T, inventory testInventory) {
		first := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
		initial, err := inventory.Save(context.Background(), []devices.Device{{
			IP: netip.MustParseAddr("192.0.2.10"), MAC: "aa:bb:cc:dd:ee:ff", Name: "printer",
			OpenPorts: []uint16{80}, FirstSeen: first, LastSeen: first,
		}})
		if err != nil {
			t.Fatal(err)
		}
		later := first.Add(time.Hour)
		moved, err := inventory.Save(context.Background(), []devices.Device{{
			IP: netip.MustParseAddr("192.0.2.25"), MAC: "AA-BB-CC-DD-EE-FF",
			OpenPorts: []uint16{443}, FirstSeen: later, LastSeen: later,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if moved[0].ID != initial[0].ID || moved[0].Name != "printer" || moved[0].FirstSeen != first {
			t.Fatalf("moved device lost durable identity: %#v", moved[0])
		}
		items, err := inventory.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].IP != netip.MustParseAddr("192.0.2.25") {
			t.Fatalf("inventory after address change = %#v", items)
		}
	})
}

func TestInventoryDoesNotReuseIdentityForDifferentMACAtSameAddress(t *testing.T) {
	testInventories(t, func(t *testing.T, inventory testInventory) {
		address := netip.MustParseAddr("192.0.2.10")
		first, err := inventory.Save(context.Background(), []devices.Device{{
			IP: address, MAC: "aa:bb:cc:dd:ee:ff",
		}})
		if err != nil {
			t.Fatal(err)
		}
		replacement, err := inventory.Save(context.Background(), []devices.Device{{
			IP: address, MAC: "00:11:22:33:44:55",
		}})
		if err != nil {
			t.Fatal(err)
		}
		if replacement[0].ID == first[0].ID {
			t.Fatalf("different device reused ID %q", first[0].ID)
		}
		items, err := inventory.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].MAC != "00:11:22:33:44:55" {
			t.Fatalf("inventory after address reuse = %#v", items)
		}
	})
}

func TestInventoryListSortsAndReturnsCopies(t *testing.T) {
	testInventories(t, func(t *testing.T, inventory testInventory) {
		now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
		_, err := inventory.Save(context.Background(), []devices.Device{
			{IP: netip.MustParseAddr("192.0.2.20"), OpenPorts: []uint16{80}, OpenUDPPorts: []uint16{53}, FirstSeen: now, LastSeen: now},
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
		items[1].OpenUDPPorts[0] = 9999
		stored, err := inventory.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if stored[0].OpenPorts[0] != 22 {
			t.Fatalf("stored port changed through returned slice: %d", stored[0].OpenPorts[0])
		}
		if stored[1].OpenUDPPorts[0] != 53 {
			t.Fatalf("stored UDP port changed through returned slice: %d", stored[1].OpenUDPPorts[0])
		}
	})
}

func TestInventorySavePreservesInputOrderAndReturnsCopies(t *testing.T) {
	testInventories(t, func(t *testing.T, inventory testInventory) {
		now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
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
	})
}

func TestInventoryRejectsInvalidBatchWithoutChangingInventory(t *testing.T) {
	testInventories(t, func(t *testing.T, inventory testInventory) {
		_, err := inventory.Save(context.Background(), []devices.Device{{
			IP: netip.MustParseAddr("192.0.2.1"), Name: "existing",
		}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = inventory.Save(context.Background(), []devices.Device{
			{IP: netip.MustParseAddr("192.0.2.2"), Name: "would be added"},
			{Name: "invalid"},
		})
		if err == nil {
			t.Fatal("Save accepted a device without an IP address")
		}
		items, err := inventory.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].Name != "existing" {
			t.Fatalf("invalid batch changed inventory: %#v", items)
		}
	})
}

func TestSQLiteInventoryPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.db")
	first := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	inventory, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := inventory.Save(context.Background(), []devices.Device{{
		IP: netip.MustParseAddr("192.0.2.10"), MAC: "aa:bb:cc:dd:ee:ff", Name: "printer",
		OpenPorts: []uint16{80}, OpenUDPPorts: []uint16{161}, DiscoveredBy: []string{"tcp", "udp"}, FirstSeen: first, LastSeen: first,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close inventory: %v", err)
		}
	})
	items, err := reopened.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != created[0].ID || items[0].Name != "printer" || items[0].FirstSeen != first || len(items[0].OpenUDPPorts) != 1 || items[0].OpenUDPPorts[0] != 161 {
		t.Fatalf("reopened inventory = %#v", items)
	}
}
