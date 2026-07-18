package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type ssdpIdentitySource struct {
	timeout     time.Duration
	concurrency int
}

type ssdpLocation struct {
	address netip.Addr
	url     string
}

type ssdpDescription struct {
	Device struct {
		FriendlyName string `xml:"friendlyName"`
	} `xml:"device"`
}

func newSSDPIdentitySource(timeout time.Duration, concurrency int) IdentitySource {
	if timeout < 1200*time.Millisecond {
		timeout = 1200 * time.Millisecond
	}
	if concurrency < 1 {
		concurrency = 1
	}
	return ssdpIdentitySource{timeout: timeout, concurrency: min(concurrency, 64)}
}

func (source ssdpIdentitySource) Discover(ctx context.Context, prefix netip.Prefix) ([]Identity, error) {
	localAddress, err := localIPv4ForPrefix(prefix)
	if err != nil {
		return nil, err
	}
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(localAddress.AsSlice())})
	if err != nil {
		return nil, fmt.Errorf("listen for SSDP: %w", err)
	}
	defer connection.Close()

	request := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		`MAN: "ssdp:discover"`,
		"MX: 1",
		"ST: ssdp:all",
		"",
		"",
	}, "\r\n")
	group := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	if _, err := connection.WriteToUDP([]byte(request), group); err != nil {
		return nil, fmt.Errorf("send SSDP search: %w", err)
	}

	deadline := time.Now().Add(source.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set SSDP deadline: %w", err)
	}

	locations := make(map[string]ssdpLocation)
	buffer := make([]byte, 64*1024)
	for {
		length, remote, err := connection.ReadFromUDP(buffer)
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				break
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("receive SSDP response: %w", err)
		}
		remoteAddress, ok := netip.AddrFromSlice(remote.IP)
		if !ok || !remoteAddress.Is4() || !prefix.Contains(remoteAddress.Unmap()) {
			continue
		}
		location, ok := parseSSDPLocation(buffer[:length], prefix)
		if !ok {
			continue
		}
		locations[location.url] = location
	}

	return source.fetchDescriptions(ctx, prefix, locations), nil
}

func parseSSDPLocation(packet []byte, prefix netip.Prefix) (ssdpLocation, bool) {
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(packet)), &http.Request{Method: "M-SEARCH"})
	if err != nil {
		return ssdpLocation{}, false
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ssdpLocation{}, false
	}
	location := strings.TrimSpace(response.Header.Get("Location"))
	parsed, err := url.Parse(location)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ssdpLocation{}, false
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.Is4() || !prefix.Contains(address) {
		return ssdpLocation{}, false
	}
	return ssdpLocation{address: address, url: parsed.String()}, true
}

func (source ssdpIdentitySource) fetchDescriptions(ctx context.Context, prefix netip.Prefix, locations map[string]ssdpLocation) []Identity {
	if len(locations) == 0 {
		return nil
	}
	jobs := make(chan ssdpLocation)
	results := make(chan Identity)
	workerCount := min(source.concurrency, len(locations))
	client, transport := source.descriptionClient(prefix)
	defer transport.CloseIdleConnections()
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for location := range jobs {
				if observation, ok := source.fetchDescriptionWithClient(ctx, client, location); ok {
					select {
					case results <- observation:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, location := range locations {
			select {
			case jobs <- location:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	byAddress := make(map[netip.Addr]Identity)
	for observation := range results {
		existing := byAddress[observation.IP]
		if existing.Name == "" || observation.Name < existing.Name {
			byAddress[observation.IP] = observation
		}
	}
	observations := make([]Identity, 0, len(byAddress))
	for _, observation := range byAddress {
		observations = append(observations, observation)
	}
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].IP.Compare(observations[j].IP) < 0
	})
	return observations
}

func (source ssdpIdentitySource) fetchDescription(ctx context.Context, prefix netip.Prefix, location ssdpLocation) (Identity, bool) {
	client, transport := source.descriptionClient(prefix)
	defer transport.CloseIdleConnections()
	return source.fetchDescriptionWithClient(ctx, client, location)
}

func (source ssdpIdentitySource) descriptionClient(prefix netip.Prefix) (*http.Client, *http.Transport) {
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: source.timeout}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   source.timeout,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			address, err := netip.ParseAddr(request.URL.Hostname())
			if err != nil || !address.Is4() || !prefix.Contains(address) {
				return errors.New("SSDP redirect left scanned network")
			}
			return nil
		},
	}
	return client, transport
}

func (source ssdpIdentitySource) fetchDescriptionWithClient(ctx context.Context, client *http.Client, location ssdpLocation) (Identity, bool) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.url, nil)
	if err != nil {
		return Identity{}, false
	}
	response, err := client.Do(request)
	if err != nil {
		return Identity{}, false
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Identity{}, false
	}

	name, err := parseSSDPDescription(io.LimitReader(response.Body, 1<<20))
	if err != nil || name == "" {
		return Identity{}, false
	}
	return Identity{IP: location.address, Name: name, Method: "ssdp"}, true
}

func parseSSDPDescription(input io.Reader) (string, error) {
	var description ssdpDescription
	if err := xml.NewDecoder(input).Decode(&description); err != nil {
		return "", err
	}
	return strings.TrimSpace(description.Device.FriendlyName), nil
}
