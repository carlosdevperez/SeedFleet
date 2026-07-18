//go:build linux

package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestParseARPTableReturnsOnlyCompleteValidNeighbors(t *testing.T) {
	input := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2        0c:ef:15:d8:93:f9     *        eth0
192.168.1.5      0x1         0x0        00:00:00:00:00:00     *        eth0
not-an-ip        0x1         0x2        aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.7      0x1         0x6        e0:ef:bf:ad:56:3c     *        eth0
malformed
`

	neighbors, err := parseARPTable(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(neighbors) != 2 {
		t.Fatalf("neighbor count = %d, want 2: %#v", len(neighbors), neighbors)
	}
	if got := neighbors[0].IP.String(); got != "192.168.1.1" {
		t.Fatalf("first IP = %s, want 192.168.1.1", got)
	}
	if got := neighbors[1].MAC.String(); got != "e0:ef:bf:ad:56:3c" {
		t.Fatalf("second MAC = %s, want e0:ef:bf:ad:56:3c", got)
	}
}
