package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/baseline"
	"github.com/RatulSikder97/hostwarden/internal/checks"
	"github.com/RatulSikder97/hostwarden/internal/dockerapi"
	"github.com/RatulSikder97/hostwarden/internal/host"
	"github.com/RatulSikder97/hostwarden/internal/report"
)

// scanOptions are the flags shared by scan, fix, baseline and serve.
type scanOptions struct {
	root         string
	proc         string
	dockerSocket string
	noExec       bool
	recent       time.Duration
	only         string
	exclude      string
	baseline     string
}

func (o *scanOptions) register(fs *flag.FlagSet) {
	fs.StringVar(&o.root, "root", "/", "filesystem root to audit (e.g. a mounted disk image or /host)")
	fs.StringVar(&o.proc, "proc", "", "procfs path (default /proc for --root /, otherwise <root>/proc)")
	fs.StringVar(&o.dockerSocket, "docker-socket", "", "Docker API socket (default: <root>/run/docker.sock when present)")
	fs.BoolVar(&o.noExec, "no-exec", false, "never run read-only package-manager probes (apt-get -s, dnf updateinfo)")
	fs.DurationVar(&o.recent, "recent", 72*time.Hour, "window for 'recently modified' compromise indicators")
	fs.StringVar(&o.only, "checks", "", "comma-separated check IDs, ID prefixes (HW-SSH) or categories to run")
	fs.StringVar(&o.exclude, "exclude", "", "comma-separated check IDs, ID prefixes or categories to skip")
	fs.StringVar(&o.baseline, "baseline", "", "baseline file of accepted findings")
}

func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type execRunner struct{}

func (execRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (o *scanOptions) host() *host.Host {
	cfg := host.Config{Root: o.root, Proc: o.proc, RecentWindow: o.recent}
	if cfg.Proc == "" && filepath.Clean(o.root) == "/" {
		cfg.Proc = "/proc"
	}
	sock := o.dockerSocket
	if sock == "" {
		for _, p := range []string{"/run/docker.sock", "/var/run/docker.sock"} {
			candidate := filepath.Join(o.root, p)
			if fi, err := os.Stat(candidate); err == nil && fi.Mode()&os.ModeSocket != 0 {
				sock = candidate
				break
			}
		}
	}
	if sock != "" {
		cfg.Docker = dockerapi.Cached(dockerapi.New(sock))
	}
	if !o.noExec && filepath.Clean(o.root) == "/" {
		cfg.Exec = execRunner{}
	}
	return host.New(cfg)
}

// scan runs the selected checks and returns the report and the catalogue used.
func (o *scanOptions) scan(ctx context.Context) (*audit.Report, []audit.Check, error) {
	selected, err := checks.Select(checks.All(), splitList(o.only), splitList(o.exclude))
	if err != nil {
		return nil, nil, err
	}
	h := o.host()
	opts := audit.Options{Version: version()}
	if o.baseline != "" {
		bl, err := baseline.Load(o.baseline)
		if err != nil {
			return nil, nil, err
		}
		opts.Suppress = bl.Matcher(h.Now())
	}
	return audit.Run(ctx, h, selected, opts), selected, nil
}

func runScan(ctx context.Context, args []string, streams IO) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(streams.Stderr)
	var o scanOptions
	o.register(fs)
	format := fs.String("format", "table", "output format: table, json or sarif")
	output := fs.String("output", "", "write the report to this file instead of stdout")
	failOn := fs.String("fail-on", "none", "exit 1 if any active finding is at or above this severity (low, medium, high, critical, none)")
	color := fs.String("color", "auto", "colorize table output: auto, always or never")
	verbose := fs.Bool("verbose", false, "include evidence lines in table output")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	threshold := audit.SeverityUnset
	if *failOn != "none" {
		s, err := audit.ParseSeverity(*failOn)
		if err != nil {
			return errorf(streams.Stderr, "--fail-on: %v", err)
		}
		threshold = s
	}
	switch *format {
	case "table", "json", "sarif":
	default:
		return errorf(streams.Stderr, "--format must be table, json or sarif")
	}
	rep, catalogue, err := o.scan(ctx)
	if err != nil {
		return errorf(streams.Stderr, "%v", err)
	}

	w := streams.Stdout
	var file *os.File
	if *output != "" {
		file, err = os.Create(*output)
		if err != nil {
			return errorf(streams.Stderr, "create output: %v", err)
		}
		w = file
	}
	useColor := *color == "always" || (*color == "auto" && file == nil && isTerminal(streams.Stdout) && os.Getenv("NO_COLOR") == "")
	switch *format {
	case "json":
		err = report.JSON(w, rep)
	case "sarif":
		err = report.SARIF(w, rep, catalogue)
	default:
		err = report.Table(w, rep, report.TableOptions{Color: useColor, Verbose: *verbose})
	}
	if file != nil {
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return errorf(streams.Stderr, "write report: %v", err)
	}
	if file != nil {
		fmt.Fprintf(streams.Stderr, "hostwarden: wrote %s report to %s (score %d/100, %d active findings)\n", *format, *output, rep.Score, len(rep.Active()))
	}
	if rep.Exceeds(threshold) {
		return ExitFindings
	}
	return ExitOK
}

func runFix(ctx context.Context, args []string, streams IO) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(streams.Stderr)
	var o scanOptions
	o.register(fs)
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	rep, _, err := o.scan(ctx)
	if err != nil {
		return errorf(streams.Stderr, "%v", err)
	}
	if err := report.FixScript(streams.Stdout, rep); err != nil {
		return errorf(streams.Stderr, "write script: %v", err)
	}
	return ExitOK
}

func runBaseline(ctx context.Context, args []string, streams IO) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	fs.SetOutput(streams.Stderr)
	var o scanOptions
	o.register(fs)
	out := fs.String("o", ".hostwarden-baseline.json", "baseline file to write")
	reason := fs.String("reason", "accepted at baseline creation", "justification recorded for every entry")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	rep, _, err := o.scan(ctx)
	if err != nil {
		return errorf(streams.Stderr, "%v", err)
	}
	bl := baseline.FromReport(rep, *reason)
	if o.baseline != "" {
		// Extending an existing baseline: keep its entries, append new ones.
		prev, err := baseline.Load(o.baseline)
		if err != nil {
			return errorf(streams.Stderr, "%v", err)
		}
		bl.Accepted = append(prev.Accepted, bl.Accepted...)
	}
	b, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return errorf(streams.Stderr, "encode baseline: %v", err)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil { //nolint:gosec // baseline files are meant to be committed
		return errorf(streams.Stderr, "write baseline: %v", err)
	}
	fmt.Fprintf(streams.Stderr, "hostwarden: wrote %d accepted findings to %s\n", len(rep.Active()), *out)
	return ExitOK
}
