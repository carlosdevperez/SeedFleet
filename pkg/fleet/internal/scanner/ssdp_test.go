package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseSSDPLocation(t *testing.T) {
	packet := []byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.4:8000/device.xml\r\nST: upnp:rootdevice\r\n\r\n")
	location, ok := parseSSDPLocation(packet, netip.MustParsePrefix("192.0.2.0/24"))
	if !ok || location.url != "http://192.0.2.4:8000/device.xml" || location.address.String() != "192.0.2.4" {
		t.Fatalf("location = %#v, ok = %v", location, ok)
	}
	if _, ok := parseSSDPLocation(packet, netip.MustParsePrefix("198.51.100.0/24")); ok {
		t.Fatal("accepted SSDP location outside scanned network")
	}
}

func TestFetchSSDPDescription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(response, `<root><device><friendlyName>Living Room TV</friendlyName></device></root>`)
	}))
	defer server.Close()
	host := strings.TrimPrefix(strings.Split(server.URL, ":")[1], "//")
	address := netip.MustParseAddr(host)
	source := ssdpIdentitySource{timeout: time.Second, concurrency: 1}
	observation, ok := source.fetchDescription(context.Background(), netip.MustParsePrefix("127.0.0.0/8"), ssdpLocation{
		address: address,
		url:     server.URL,
	})
	if !ok || observation.Name != "Living Room TV" {
		t.Fatalf("observation = %#v, ok = %v", observation, ok)
	}
}
