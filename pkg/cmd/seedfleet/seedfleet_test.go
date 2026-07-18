package seedfleet

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/carlosdevperez/seedfleet/pkg/fleet"
	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

type fakeProvider struct {
	network string
	items   []devices.Device
	err     error
}

func (p *fakeProvider) Scan(_ context.Context, network string) (fleet.ScanResult, error) {
	p.network = network
	return fleet.ScanResult{Network: "192.0.2.0/24", Devices: p.items}, p.err
}

func (p *fakeProvider) List(context.Context) ([]devices.Device, error) {
	return p.items, p.err
}

func TestScanEndpoint(t *testing.T) {
	provider := &fakeProvider{items: []devices.Device{{IP: netip.MustParseAddr("192.0.2.5")}}}
	handler := newHandler(provider)
	request := httptest.NewRequest(http.MethodPost, "/scans", strings.NewReader(`{"network":"192.0.2.1/24"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if provider.network != "192.0.2.1/24" {
		t.Fatalf("network = %q", provider.network)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"network":"192.0.2.0/24"`) || !strings.Contains(body, `"count":1`) {
		t.Fatalf("body = %s", body)
	}
}

func TestListDevicesEndpoint(t *testing.T) {
	provider := &fakeProvider{items: []devices.Device{{
		IP:           netip.MustParseAddr("192.0.2.5"),
		Name:         "printer",
		OpenPorts:    []uint16{},
		OpenUDPPorts: []uint16{5353},
		DiscoveredBy: []string{"mdns"},
	}}}
	handler := newHandler(provider)
	request := httptest.NewRequest(http.MethodGet, "/devices", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"name":"printer"`) || !strings.Contains(response.Body.String(), `"openUdpPorts":[5353]`) {
		t.Fatalf("status = %d; body: %s", response.Code, response.Body.String())
	}
}

func TestScanEndpointErrors(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		body       string
		mediaType  string
		wantStatus int
	}{
		{name: "scan running", err: fleet.ErrScanInProgress, body: `{"network":"192.0.2.0/24"}`, mediaType: "application/json", wantStatus: http.StatusConflict},
		{name: "invalid network", err: &fleet.InvalidNetworkError{Reason: "not local"}, body: `{"network":"192.0.2.0/24"}`, mediaType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "internal", err: errors.New("private failure"), body: `{"network":"192.0.2.0/24"}`, mediaType: "application/json", wantStatus: http.StatusInternalServerError},
		{name: "unknown field", body: `{"network":"192.0.2.0/24","extra":true}`, mediaType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "wrong media type", body: `{"network":"192.0.2.0/24"}`, mediaType: "text/plain", wantStatus: http.StatusUnsupportedMediaType},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newHandler(&fakeProvider{err: test.err})
			request := httptest.NewRequest(http.MethodPost, "/scans", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.mediaType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	flags, err := parseFlags([]string{
		"--address", "127.0.0.1:18080",
		"--aliases", "",
		"--allow-network", "192.168.1.4/24",
		"--allow-routed-networks",
	})
	if err != nil {
		t.Fatal(err)
	}
	if flags.Address != "127.0.0.1:18080" || flags.AliasFile != "" || !flags.AllowRoutedNetworks {
		t.Fatalf("flags = %#v", flags)
	}
	if len(flags.AllowedNetworks) != 1 || flags.AllowedNetworks[0] != netip.MustParsePrefix("192.168.1.0/24") {
		t.Fatalf("allowed networks = %v", flags.AllowedNetworks)
	}
}

func TestParseFlagsRejectsUnsafeRoutedMode(t *testing.T) {
	if _, err := parseFlags([]string{"--allow-routed-networks"}); err == nil {
		t.Fatal("parseFlags accepted routed scans without an allowlist")
	}
}
