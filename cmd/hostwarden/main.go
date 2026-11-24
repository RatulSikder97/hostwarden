// Command hostwarden is a read-only Linux server security auditor and
// compromise detector.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/RatulSikder97/hostwarden/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.IO{Stdout: os.Stdout, Stderr: os.Stderr})
	stop()
	os.Exit(code)
}
