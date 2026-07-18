package scanner

import (
	"context"
	"os"
	"strings"
	"testing"

	"net/netip"
)

func TestLocalIdentitySourceDiscoversLoopback(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	observations, err := (localIdentitySource{}).Discover(context.Background(), netip.MustParsePrefix("127.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range observations {
		if observation.IP.IsLoopback() && observation.Hostname == strings.TrimSpace(hostname) {
			return
		}
	}
	t.Fatalf("loopback hostname %q not found in %#v", hostname, observations)
}
