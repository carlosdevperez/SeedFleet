package scanner

import (
	"net/netip"
	"testing"
)

func TestMDNSInstanceNamePreference(t *testing.T) {
	if got := mdnsInstanceName("Living Room TV._googlecast._tcp.local.", "_googlecast._tcp.local."); got != "Living Room TV" {
		t.Fatalf("instance name = %q", got)
	}
	if !preferMDNSName("Living Room TV", "f6bb4a6f-404d-aad8-5fd6-1226b973c1e9") {
		t.Fatal("friendly mDNS name should be preferred over UUID")
	}
	if mdnsNameScore("I05POU38n14AAA") != 0 {
		t.Fatal("opaque service identifier should not become a friendly device name")
	}
	if mdnsHostnameScore("android.local") <= mdnsHostnameScore("f6bb4a6f-404d-aad8-5fd6-1226b973c1e9.local") {
		t.Fatal("human-readable hostname should outrank UUID hostname")
	}
}

func TestMDNSObservationsHandleServiceEnumerationAfterInstance(t *testing.T) {
	service := "_custom._tcp.local."
	instance := "Office Sensor." + service
	host := "sensor.local."
	address := netip.MustParseAddr("192.168.1.20")
	records := []dnsRecord{
		{type_: dnsTypePTR, name: service, target: instance},
		{type_: dnsTypePTR, name: commonMDNSServiceTypes[0], target: service},
		{type_: dnsTypeSRV, name: instance, target: host},
		{type_: dnsTypeA, name: host, address: address},
	}

	identities := mdnsObservations(records, netip.MustParsePrefix("192.168.1.0/24"))
	if len(identities) != 1 || identities[0].Name != "Office Sensor" || identities[0].IP != address {
		t.Fatalf("identities = %#v", identities)
	}
}
