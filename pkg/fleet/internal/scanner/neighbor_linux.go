//go:build linux

package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type procNeighborSource struct {
	path string
}

func newSystemNeighborSource() NeighborSource {
	return procNeighborSource{path: "/proc/net/arp"}
}

func (source procNeighborSource) List(ctx context.Context) ([]Neighbor, error) {
	file, err := os.Open(source.path)
	if err != nil {
		return nil, fmt.Errorf("open neighbor table: %w", err)
	}
	defer file.Close()
	return parseARPTable(ctx, file)
}

func parseARPTable(ctx context.Context, input io.Reader) ([]Neighbor, error) {
	scanner := bufio.NewScanner(input)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read neighbor table header: %w", err)
		}
		return nil, nil
	}

	neighbors := make([]Neighbor, 0)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		flags, err := strconv.ParseUint(fields[2], 0, 32)
		if err != nil || flags&0x2 == 0 { // ATF_COM: address resolution completed.
			continue
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil || !address.Is4() {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil || isZeroMAC(mac) {
			continue
		}
		neighbors = append(neighbors, Neighbor{IP: address, MAC: mac})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read neighbor table: %w", err)
	}
	return neighbors, nil
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, octet := range mac {
		if octet != 0 {
			return false
		}
	}
	return true
}
