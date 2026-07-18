package scanner

import (
	"bytes"
	"net/netip"
	"testing"
)

// These fuzz targets cover every parser that consumes LAN protocol packets.
func FuzzParseDNSRecords(f *testing.F) {
	f.Add(make([]byte, 12))
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = parseDNSRecords(packet)
	})
}

func FuzzDecodeDNSName(f *testing.F) {
	f.Add([]byte{0}, uint16(0))
	f.Add([]byte{0xc0, 0x00}, uint16(0))
	f.Add([]byte{3, 'l', 'a', 'n', 0}, uint16(0))
	f.Fuzz(func(t *testing.T, packet []byte, rawStart uint16) {
		start := 0
		if len(packet) > 0 {
			start = int(rawStart) % len(packet)
		}
		_, _, _ = decodeDNSName(packet, start)
	})
}

func FuzzParseSSDPLocation(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.4/device.xml\r\n\r\n"))
	f.Add([]byte("not HTTP"))
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = parseSSDPLocation(packet, prefix)
	})
}

func FuzzParseSSDPDescription(f *testing.F) {
	f.Add([]byte(`<root><device><friendlyName>Living Room TV</friendlyName></device></root>`))
	f.Add([]byte(`<root>`))
	f.Fuzz(func(t *testing.T, document []byte) {
		_, _ = parseSSDPDescription(bytes.NewReader(document))
	})
}
