// Package cli implements the hostwarden command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// Version is overridden at build time via -ldflags "-X .../internal/cli.Version=...".
var Version = ""

func version() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// IO bundles the process streams so commands are testable.
type IO struct {
	Stdout io.Writer
	Stderr io.Writer
}

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, io IO) int
}

func commands() []command {
	return []command{
		{"scan", "audit this host (or a mounted root) and report findings", runScan},
		{"fix", "print a remediation script for current findings (never executes it)", runFix},
		{"baseline", "write a baseline file accepting the current findings", runBaseline},
		{"checks", "list the check catalogue", runChecks},
		{"fleet", "scan many hosts over SSH and aggregate the results", runFleet},
		{"serve", "run as a Prometheus exporter (--metrics)", runServe},
		{"version", "print the version", func(_ context.Context, _ []string, io IO) int {
			fmt.Fprintf(io.Stdout, "hostwarden %s\n", version())
			return ExitOK
		}},
	}
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, streams IO) int {
	if len(args) == 0 {
		usage(streams.Stderr)
		return ExitError
	}
	name := args[0]
	switch name {
	case "-h", "--help", "help":
		usage(streams.Stdout)
		return ExitOK
	case "-v", "--version":
		name = "version"
	}
	for _, c := range commands() {
		if c.name == name {
			return c.run(ctx, args[1:], streams)
		}
	}
	fmt.Fprintf(streams.Stderr, "hostwarden: unknown command %q\n\n", name)
	usage(streams.Stderr)
	return ExitError
}

func usage(w io.Writer) {
	var b strings.Builder
	b.WriteString("hostwarden: read-only Linux server security auditor and compromise detector\n\n")
	b.WriteString("Usage:\n  hostwarden <command> [flags]\n\nCommands:\n")
	for _, c := range commands() {
		fmt.Fprintf(&b, "  %-9s %s\n", c.name, c.summary)
	}
	b.WriteString("\nRun 'hostwarden <command> -h' for command flags.\n")
	_, _ = io.WriteString(w, b.String())
}

// parseFlags parses args, printing errors to stderr. It returns false and an
// exit code if the command should stop.
func parseFlags(fs *flag.FlagSet, args []string) (bool, int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, ExitOK
		}
		return false, ExitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return false, ExitError
	}
	return true, ExitOK
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func errorf(w io.Writer, format string, args ...any) int {
	fmt.Fprintf(w, "hostwarden: "+format+"\n", args...)
	return ExitError
}
