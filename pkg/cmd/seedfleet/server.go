// Package seedfleet implements the SeedFleet server command.
package seedfleet

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet"
)

type flagpole struct {
	Address             string
	AliasFile           string
	DatabaseFile        string
	AllowedNetworks     prefixList
	AllowRoutedNetworks bool
}

// Run parses args and serves requests until ctx is canceled.
func Run(ctx context.Context, args []string) error {
	flags, err := parseFlags(args)
	if err != nil {
		return err
	}
	options := []fleet.ProviderOption{
		fleet.ProviderWithAliasFile(flags.AliasFile),
		fleet.ProviderWithAllowedNetworks(flags.AllowedNetworks...),
	}
	if flags.AllowRoutedNetworks {
		options = append(options, fleet.ProviderWithRoutedNetworks())
	}
	if flags.DatabaseFile != "" {
		options = append(options, fleet.ProviderWithSQLiteInventory(flags.DatabaseFile))
	}
	provider, err := fleet.NewProvider(options...)
	if err != nil {
		return err
	}
	defer func() {
		if err := provider.Close(); err != nil {
			log.Printf("inventory shutdown: %v", err)
		}
	}()

	server := &http.Server{
		Addr:              flags.Address,
		Handler:           newHandler(provider),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// A complete TCP and UDP port sweep can legitimately take longer than a
		// server-wide timeout. Client cancellation still stops the scan, and the
		// Docker deployment handler applies its own bounded timeout.
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}
	serverContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go shutdownOnCancellation(serverContext, server)

	log.Printf("SeedFleet listening on http://%s", flags.Address)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to serve SeedFleet API: %w", err)
	}
	return nil
}

func parseFlags(args []string) (*flagpole, error) {
	flags := &flagpole{}
	set := flag.NewFlagSet("seedfleet", flag.ContinueOnError)
	set.StringVar(&flags.Address, "address", "127.0.0.1:8080", "HTTP server listen address")
	set.StringVar(&flags.AliasFile, "aliases", "device-aliases.json", "optional JSON file mapping MAC addresses to device identities")
	set.StringVar(&flags.DatabaseFile, "database", "", "SQLite inventory file; empty keeps inventory in memory")
	set.Var(&flags.AllowedNetworks, "allow-network", "CIDR that may be scanned; repeat for multiple networks")
	set.BoolVar(&flags.AllowRoutedNetworks, "allow-routed-networks", false, "allow allowlisted networks that are not directly connected")
	if err := set.Parse(args); err != nil {
		return nil, err
	}
	if set.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(set.Args(), " "))
	}
	if flags.AllowRoutedNetworks && len(flags.AllowedNetworks) == 0 {
		return nil, errors.New("--allow-routed-networks requires at least one --allow-network")
	}
	return flags, nil
}

type prefixList []netip.Prefix

func (p *prefixList) Set(raw string) error {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("allow-network must be an IPv4 CIDR: %q", raw)
	}
	*p = append(*p, prefix.Masked())
	return nil
}

func (p *prefixList) String() string {
	values := make([]string, len(*p))
	for index, prefix := range *p {
		values[index] = prefix.String()
	}
	return strings.Join(values, ",")
}

func shutdownOnCancellation(ctx context.Context, server *http.Server) {
	<-ctx.Done()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		log.Printf("HTTP shutdown: %v", err)
	}
}
