package scanner

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseDNSRecordsHandlesCompressedResponse(t *testing.T) {
	questionName, err := encodeDNSName("_http._tcp.local.")
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[6:8], 3)
	packet = append(packet, questionName...)
	packet = binary.BigEndian.AppendUint16(packet, dnsTypePTR)
	packet = binary.BigEndian.AppendUint16(packet, 1)

	instance, _ := encodeDNSName("Living Room._http._tcp.local.")
	packet = appendTestDNSRecord(packet, []byte{0xc0, 0x0c}, dnsTypePTR, instance)

	serverName, _ := encodeDNSName("speaker.local.")
	srvData := make([]byte, 6)
	binary.BigEndian.PutUint16(srvData[4:6], 8080)
	srvData = append(srvData, serverName...)
	packet = appendTestDNSRecord(packet, instance, dnsTypeSRV, srvData)
	packet = appendTestDNSRecord(packet, serverName, dnsTypeA, []byte{192, 168, 1, 2})

	records, err := parseDNSRecords(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("record count = %d, want 3", len(records))
	}
	if records[0].target != "Living Room._http._tcp.local." {
		t.Fatalf("PTR target = %q", records[0].target)
	}
	if records[1].target != "speaker.local." {
		t.Fatalf("SRV target = %q", records[1].target)
	}
	if records[2].address != netip.MustParseAddr("192.168.1.2") {
		t.Fatalf("A address = %s", records[2].address)
	}
}

func TestDecodeDNSNameRejectsPointerLoop(t *testing.T) {
	if _, _, err := decodeDNSName([]byte{0xc0, 0x00}, 0); err == nil {
		t.Fatal("expected a compression pointer loop error")
	}
}

func appendTestDNSRecord(packet, name []byte, recordType uint16, data []byte) []byte {
	packet = append(packet, name...)
	packet = binary.BigEndian.AppendUint16(packet, recordType)
	packet = binary.BigEndian.AppendUint16(packet, 1)
	packet = binary.BigEndian.AppendUint32(packet, 120)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(data)))
	return append(packet, data...)
}
