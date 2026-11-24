package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/fleet"
)

// binaryFlag accepts "PATH" (used for every arch) or repeated "ARCH=PATH".
type binaryFlag map[string]string

func (b binaryFlag) String() string { return fmt.Sprint(map[string]string(b)) }

func (b binaryFlag) Set(v string) error {
	if arch, p, ok := strings.Cut(v, "="); ok {
		if arch != "amd64" && arch != "arm64" {
			return fmt.Errorf("unsupported arch %q (want amd64 or arm64)", arch)
		}
		b[arch] = p
		return nil
	}
	b["amd64"], b["arm64"] = v, v
	return nil
}

func runFleet(ctx context.Context, args []string, streams IO) int {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	fs.SetOutput(streams.Stderr)
	inventory := fs.String("i", "", "inventory YAML file (required)")
	binaries := binaryFlag{}
	fs.Var(binaries, "binary", "linux hostwarden binary to upload: PATH, or ARCH=PATH (repeatable). Defaults to this executable on linux")
	format := fs.String("format", "table", "output format: table or json")
	conc := fs.Int("concurrency", 8, "hosts scanned in parallel")
	timeout := fs.Duration("timeout", 5*time.Minute, "per-host timeout")
	failOn := fs.String("fail-on", "none", "exit 1 if any host has an active finding at or above this severity")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	if *inventory == "" {
		return errorf(streams.Stderr, "fleet: -i inventory.yaml is required")
	}
	if *format != "table" && *format != "json" {
		return errorf(streams.Stderr, "fleet: --format must be table or json")
	}
	threshold := audit.SeverityUnset
	if *failOn != "none" {
		s, err := audit.ParseSeverity(*failOn)
		if err != nil {
			return errorf(streams.Stderr, "--fail-on: %v", err)
		}
		threshold = s
	}
	if len(binaries) == 0 {
		if runtime.GOOS != "linux" {
			return errorf(streams.Stderr, "fleet: pass --binary with a linux build (e.g. from the release archives)")
		}
		self, err := os.Executable()
		if err != nil {
			return errorf(streams.Stderr, "fleet: locate own executable: %v", err)
		}
		binaries[runtime.GOARCH] = self
	}
	inv, err := fleet.LoadInventory(*inventory)
	if err != nil {
		return errorf(streams.Stderr, "fleet: %v", err)
	}
	ag, closeAgent, err := fleet.AgentFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(streams.Stderr, "hostwarden: warning: %v\n", err)
	}
	defer closeAgent()

	results := fleet.Run(ctx, inv, fleet.Options{Binaries: binaries, Concurrency: *conc, Timeout: *timeout, Agent: ag})
	sum := fleet.Summarize(results, time.Now())
	if *format == "json" {
		err = sum.WriteJSON(streams.Stdout)
	} else {
		err = sum.WriteTable(streams.Stdout)
	}
	if err != nil {
		return errorf(streams.Stderr, "write fleet report: %v", err)
	}
	switch {
	case sum.Failed > 0:
		return ExitError
	case sum.Exceeds(threshold):
		return ExitFindings
	}
	return ExitOK
}
