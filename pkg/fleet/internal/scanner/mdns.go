package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

var commonMDNSServiceTypes = []string{
	"_services._dns-sd._udp.local.",
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_ssh._tcp.local.",
	"_smb._tcp.local.",
	"_workstation._tcp.local.",
	"_device-info._tcp.local.",
	"_ipp._tcp.local.",
	"_ipps._tcp.local.",
	"_printer._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_googlecast._tcp.local.",
	"_companion-link._tcp.local.",
	"_hap._tcp.local.",
	"_matter._tcp.local.",
	"_matterc._udp.local.",
	"_matterd._udp.local.",
}

type mdnsIdentitySource struct {
	timeout time.Duration
}

func newMDNSIdentitySource(timeout time.Duration) IdentitySource {
	if timeout < 400*time.Millisecond {
		timeout = 400 * time.Millisecond
	}
	return mdnsIdentitySource{timeout: timeout}
}

func (source mdnsIdentitySource) Discover(ctx context.Context, prefix netip.Prefix) ([]Identity, error) {
	iface, err := interfaceForPrefix(prefix)
	if err != nil {
		return nil, err
	}
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	connection, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		return nil, fmt.Errorf("listen for mDNS: %w", err)
	}
	defer connection.Close()
	_ = connection.SetReadBuffer(64 * 1024)

	records, err := source.browse(ctx, connection, group)
	if err != nil {
		return nil, err
	}
	return mdnsObservations(records, prefix), nil
}

func (source mdnsIdentitySource) browse(ctx context.Context, connection *net.UDPConn, group *net.UDPAddr) ([]dnsRecord, error) {
	initial := make([]dnsQuestion, 0, len(commonMDNSServiceTypes))
	for _, serviceType := range commonMDNSServiceTypes {
		initial = append(initial, dnsQuestion{name: serviceType, type_: dnsTypePTR})
	}
	allRecords, err := source.exchange(ctx, connection, group, initial)
	if err != nil {
		return nil, err
	}

	serviceTypes := make(map[string]struct{}, len(commonMDNSServiceTypes))
	for _, serviceType := range commonMDNSServiceTypes[1:] {
		serviceTypes[canonicalDNSName(serviceType)] = struct{}{}
	}
	metaName := canonicalDNSName(commonMDNSServiceTypes[0])
	for _, record := range allRecords {
		if record.type_ == dnsTypePTR && canonicalDNSName(record.name) == metaName && record.target != "" {
			serviceTypes[canonicalDNSName(record.target)] = struct{}{}
		}
	}
	questions := questionsForNames(serviceTypes, dnsTypePTR)
	records, err := source.exchange(ctx, connection, group, questions)
	if err != nil {
		return nil, err
	}
	allRecords = append(allRecords, records...)

	instances := make(map[string]struct{})
	for _, record := range allRecords {
		if record.type_ == dnsTypePTR && record.target != "" {
			if _, ok := serviceTypes[canonicalDNSName(record.name)]; ok {
				instances[canonicalDNSName(record.target)] = struct{}{}
			}
		}
	}
	records, err = source.exchange(ctx, connection, group, questionsForNames(instances, dnsTypeSRV))
	if err != nil {
		return nil, err
	}
	allRecords = append(allRecords, records...)

	targets := make(map[string]struct{})
	for _, record := range allRecords {
		if record.type_ == dnsTypeSRV && record.target != "" {
			targets[canonicalDNSName(record.target)] = struct{}{}
		}
	}
	records, err = source.exchange(ctx, connection, group, questionsForNames(targets, dnsTypeA))
	if err != nil {
		return nil, err
	}
	return append(allRecords, records...), nil
}

func questionsForNames(names map[string]struct{}, recordType uint16) []dnsQuestion {
	questions := make([]dnsQuestion, 0, len(names))
	for name := range names {
		questions = append(questions, dnsQuestion{name: name, type_: recordType})
	}
	return questions
}

func mdnsObservations(records []dnsRecord, prefix netip.Prefix) []Identity {
	hostAddresses := make(map[string]netip.Addr)
	instanceTargets := make(map[string]string)
	instanceNames := make(map[string]string)
	serviceTypes := make(map[string]struct{})
	for _, serviceType := range commonMDNSServiceTypes[1:] {
		serviceTypes[canonicalDNSName(serviceType)] = struct{}{}
	}
	metaName := canonicalDNSName(commonMDNSServiceTypes[0])
	for _, record := range records {
		if record.type_ == dnsTypePTR && canonicalDNSName(record.name) == metaName && record.target != "" {
			serviceTypes[canonicalDNSName(record.target)] = struct{}{}
		}
	}
	for _, record := range records {
		switch record.type_ {
		case dnsTypeA:
			if record.address.Is4() && prefix.Contains(record.address) {
				hostAddresses[canonicalDNSName(record.name)] = record.address
			}
		case dnsTypeSRV:
			if record.target != "" {
				instanceTargets[canonicalDNSName(record.name)] = canonicalDNSName(record.target)
			}
		case dnsTypePTR:
			serviceType := canonicalDNSName(record.name)
			if record.target != "" {
				if _, ok := serviceTypes[serviceType]; ok {
					instanceNames[canonicalDNSName(record.target)] = mdnsInstanceName(record.target, record.name)
				}
			}
		}
	}

	byAddress := make(map[netip.Addr]Identity)
	for host, address := range hostAddresses {
		hostname := strings.TrimSuffix(host, ".")
		if !strings.HasSuffix(strings.ToLower(hostname), ".local") {
			continue
		}
		existing := byAddress[address]
		if existing.Hostname == "" || mdnsHostnameScore(hostname) > mdnsHostnameScore(existing.Hostname) {
			existing = Identity{IP: address, Hostname: hostname, Method: "mdns"}
			byAddress[address] = existing
		}
	}
	for instance, target := range instanceTargets {
		address, ok := hostAddresses[target]
		if !ok {
			continue
		}
		observation := byAddress[address]
		if candidate := instanceNames[instance]; preferMDNSName(candidate, observation.Name) {
			observation.Name = candidate
		}
		observation.IP = address
		observation.Method = "mdns"
		byAddress[address] = observation
	}
	observations := make([]Identity, 0, len(byAddress))
	for _, observation := range byAddress {
		observations = append(observations, observation)
	}
	return observations
}

func mdnsInstanceName(instance, serviceType string) string {
	instance = strings.TrimSuffix(instance, ".")
	serviceType = strings.TrimSuffix(serviceType, ".")
	suffix := "." + serviceType
	if len(instance) > len(suffix) && strings.EqualFold(instance[len(instance)-len(suffix):], suffix) {
		return strings.TrimSpace(instance[:len(instance)-len(suffix)])
	}
	return ""
}

func preferMDNSName(candidate, existing string) bool {
	candidateScore := mdnsNameScore(candidate)
	existingScore := mdnsNameScore(existing)
	return candidateScore > existingScore || (candidateScore == existingScore && candidateScore > 0 && candidate < existing)
}

func mdnsNameScore(name string) int {
	name = strings.TrimSpace(name)
	if name == "" || looksLikeUUID(name) || looksOpaqueIdentifier(name) {
		return 0
	}
	if strings.ContainsAny(name, " _") {
		return 4
	}
	return 3
}

func mdnsHostnameScore(hostname string) int {
	label := strings.TrimSuffix(hostname, ".local")
	if looksLikeUUID(label) || looksOpaqueIdentifier(label) {
		return 0
	}
	return 1
}

func (source mdnsIdentitySource) exchange(ctx context.Context, connection *net.UDPConn, group *net.UDPAddr, questions []dnsQuestion) ([]dnsRecord, error) {
	if len(questions) == 0 {
		return nil, nil
	}
	const questionsPerPacket = 20
	packets := make([][]byte, 0, (len(questions)+questionsPerPacket-1)/questionsPerPacket)
	for start := 0; start < len(questions); start += questionsPerPacket {
		end := min(start+questionsPerPacket, len(questions))
		packet, err := buildDNSQuery(questions[start:end])
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}
	send := func() error {
		for _, packet := range packets {
			if _, err := connection.WriteToUDP(packet, group); err != nil {
				return fmt.Errorf("send mDNS query: %w", err)
			}
		}
		return nil
	}
	if err := send(); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(source.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	resendInterval := source.timeout / 3
	nextResend := time.Now().Add(resendInterval)
	buffer := make([]byte, 64*1024)
	records := make([]dnsRecord, 0)
	for {
		now := time.Now()
		if !now.Before(deadline) {
			return records, ctx.Err()
		}
		if !now.Before(nextResend) {
			if err := send(); err != nil {
				return nil, err
			}
			nextResend = now.Add(resendInterval)
		}
		readDeadline := minTime(deadline, nextResend)
		if err := connection.SetReadDeadline(readDeadline); err != nil {
			return nil, fmt.Errorf("set mDNS deadline: %w", err)
		}
		length, _, err := connection.ReadFromUDP(buffer)
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				continue
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("receive mDNS response: %w", err)
		}
		if parsed, err := parseDNSRecords(buffer[:length]); err == nil {
			records = append(records, parsed...)
		}
	}
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
