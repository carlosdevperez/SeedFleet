package scanner

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

type localIdentitySource struct{}

func newLocalIdentitySource() IdentitySource {
	return localIdentitySource{}
}

func (localIdentitySource) Discover(ctx context.Context, prefix netip.Prefix) ([]Identity, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read local hostname: %w", err)
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return nil, nil
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list local interfaces: %w", err)
	}
	observations := make([]Identity, 0, 1)
	for _, iface := range interfaces {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			parsed, err := netip.ParsePrefix(address.String())
			if err != nil || !parsed.Addr().Is4() || !prefix.Contains(parsed.Addr()) {
				continue
			}
			observations = append(observations, Identity{
				IP:       parsed.Addr(),
				Name:     hostname,
				Hostname: hostname,
				Method:   "local",
			})
		}
	}
	return observations, nil
}
