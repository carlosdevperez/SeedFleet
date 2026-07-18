package scanner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// InvalidNetworkError reports a scan request outside the configured bounds.
type InvalidNetworkError struct {
	Reason string
}

func (e *InvalidNetworkError) Error() string {
	return e.Reason
}

func validateNetwork(network string, maximum uint64) (netip.Prefix, uint64, error) {
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("invalid network %q: %w", network, err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, 0, errors.New("only IPv4 networks are supported for now")
	}
	count := uint64(1) << (32 - prefix.Bits())
	if maximum > 0 && count > maximum {
		return netip.Prefix{}, 0, fmt.Errorf("network contains %d addresses; maximum is %d", count, maximum)
	}
	return prefix, count, nil
}

func (s *Scanner) prepareNetwork(network string) (netip.Prefix, uint64, error) {
	if err := s.validateConfig(); err != nil {
		return netip.Prefix{}, 0, err
	}
	prefix, count, err := validateNetwork(network, s.config.MaxAddresses)
	if err != nil {
		return netip.Prefix{}, 0, invalidNetwork("%s", err.Error())
	}
	if err := s.validateAllowlist(prefix); err != nil {
		return netip.Prefix{}, 0, err
	}
	if s.config.AllowRoutedNetworks {
		if len(s.config.AllowedNetworks) == 0 {
			return netip.Prefix{}, 0, errors.New("routed network scans require at least one allowed network")
		}
		return prefix, count, nil
	}

	connected, err := s.interfacePrefixes()
	if err != nil {
		return netip.Prefix{}, 0, err
	}
	for _, local := range connected {
		if local.Addr().Is4() && prefixContainsPrefix(local, prefix) {
			return prefix, count, nil
		}
	}
	return netip.Prefix{}, 0, invalidNetwork("network %s is not directly connected", prefix)
}

func (s *Scanner) validateAllowlist(prefix netip.Prefix) error {
	if len(s.config.AllowedNetworks) == 0 {
		return nil
	}
	for _, allowed := range s.config.AllowedNetworks {
		if !allowed.IsValid() || !allowed.Addr().Is4() {
			return errors.New("scanner allowlist contains an invalid IPv4 network")
		}
		if prefixContainsPrefix(allowed, prefix) {
			return nil
		}
	}
	return invalidNetwork("network %s is outside the configured allowlist", prefix)
}

func invalidNetwork(format string, arguments ...any) error {
	reason := format
	if len(arguments) > 0 {
		reason = fmt.Sprintf(format, arguments...)
	}
	return &InvalidNetworkError{Reason: reason}
}

func prefixContainsPrefix(parent, child netip.Prefix) bool {
	parent = parent.Masked()
	child = child.Masked()
	return parent.IsValid() && child.IsValid() &&
		parent.Addr().BitLen() == child.Addr().BitLen() &&
		child.Bits() >= parent.Bits() && parent.Contains(child.Addr())
}

func systemInterfacePrefixes() ([]netip.Prefix, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	prefixes := make([]netip.Prefix, 0)
	for index := range interfaces {
		if interfaces[index].Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := interfaces[index].Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			parsed, err := netip.ParsePrefix(address.String())
			if err == nil && parsed.Addr().Is4() {
				prefixes = append(prefixes, parsed.Masked())
			}
		}
	}
	return prefixes, nil
}

func usableAddressCount(prefix netip.Prefix, count uint64) uint64 {
	if prefix.Bits() <= 30 {
		return count - 2
	}
	return count
}

func forEachUsableAddress(prefix netip.Prefix, count uint64, visit func(netip.Addr) bool) {
	address := prefix.Addr()
	for index := uint64(0); index < count; index++ {
		reserved := prefix.Bits() <= 30 && (index == 0 || index == count-1)
		if !reserved && !visit(address) {
			return
		}
		address = address.Next()
	}
}

func isReservedAddress(prefix netip.Prefix, count uint64, address netip.Addr) bool {
	if prefix.Bits() > 30 {
		return false
	}
	firstBytes := prefix.Addr().As4()
	lastBytes := firstBytes
	binary.BigEndian.PutUint32(lastBytes[:], binary.BigEndian.Uint32(firstBytes[:])+uint32(count-1))
	return address == prefix.Addr() || address == netip.AddrFrom4(lastBytes)
}

func interfaceForPrefix(prefix netip.Prefix) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	for index := range interfaces {
		if interfaces[index].Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := interfaces[index].Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			parsed, err := netip.ParsePrefix(address.String())
			if err == nil && parsed.Addr().Is4() && prefixContainsPrefix(parsed, prefix) {
				return &interfaces[index], nil
			}
		}
	}
	return nil, fmt.Errorf("no local interface belongs to %s", prefix)
}

func localIPv4ForPrefix(prefix netip.Prefix) (netip.Addr, error) {
	iface, err := interfaceForPrefix(prefix)
	if err != nil {
		return netip.Addr{}, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("list addresses for %s: %w", iface.Name, err)
	}
	for _, address := range addresses {
		parsed, err := netip.ParsePrefix(address.String())
		if err == nil && parsed.Addr().Is4() && prefixContainsPrefix(parsed, prefix) {
			return parsed.Addr(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no IPv4 address on %s belongs to %s", iface.Name, prefix)
}
