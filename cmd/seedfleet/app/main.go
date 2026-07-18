// Package app implements the SeedFleet application entrypoint.
package app

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	seedfleetcmd "github.com/carlosdevperez/seedfleet/pkg/cmd/seedfleet"
)

// Main is the SeedFleet main function. It exits non-zero when Run fails.
func Main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := seedfleetcmd.Run(ctx, os.Args[1:]); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}
