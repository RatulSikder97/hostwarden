// Package report renders audit reports as a terminal table, JSON, SARIF and
// remediation scripts.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *audit.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Muted ANSI styles: color only encodes severity, everything else stays plain.
var severityStyle = map[audit.Severity]string{
	audit.Critical: "\x1b[1;31m",
	audit.High:     "\x1b[31m",
	audit.Medium:   "\x1b[33m",
	audit.Low:      "\x1b[36m",
	audit.Info:     "\x1b[2m",
}

const (
	dim   = "\x1b[2m"
	bold  = "\x1b[1m"
	reset = "\x1b[0m"
)

// TableOptions tunes table rendering.
type TableOptions struct {
	Color bool
	// Width caps the message column; 0 means 100.
	Width int
	// Verbose prints evidence lines under each finding.
	Verbose bool
}

// Table writes a human-readable findings table and summary.
func Table(w io.Writer, r *audit.Report, opts TableOptions) error {
	paint := func(style, s string) string {
		if !opts.Color || style == "" {
			return s
		}
		return style + s + reset
	}
	width := opts.Width
	if width <= 0 {
		width = 100
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s  %s\n", paint(bold, "hostwarden"), r.Version, paint(dim, fmt.Sprintf("%s · %s · root=%s", r.Host.Hostname, orUnknown(r.Host.OS), r.Host.Root)))
	b.WriteString("\n")

	active := r.Active()
	if len(active) == 0 {
		b.WriteString("No findings.\n")
	} else {
		idW, tgtW := len("CHECK"), len("TARGET")
		for _, f := range active {
			idW = max(idW, len(f.CheckID))
			tgtW = max(tgtW, min(utf8.RuneCountInString(f.Target), 44))
		}
		fmt.Fprintf(&b, "%-8s  %-*s  %-*s  %s\n", "SEVERITY", idW, "CHECK", tgtW, "TARGET", "FINDING")
		for _, f := range active {
			sev := fmt.Sprintf("%-8s", strings.ToUpper(f.Severity.String()))
			fmt.Fprintf(&b, "%s  %-*s  %s  %s\n",
				paint(severityStyle[f.Severity], sev), idW, f.CheckID, pad(truncate(f.Target, 44), tgtW), truncate(f.Message, width))
			if opts.Verbose {
				for _, e := range f.Evidence {
					fmt.Fprintf(&b, "%*s%s\n", 10+idW+2+tgtW+2, "", paint(dim, "· "+truncate(e, width)))
				}
			}
		}
	}

	b.WriteString("\n")
	var parts []string
	for s := audit.Critical; s >= audit.Low; s-- {
		n := r.Summary[s.String()]
		label := fmt.Sprintf("%d %s", n, s)
		if n > 0 {
			label = paint(severityStyle[s], label)
		}
		parts = append(parts, label)
	}
	fmt.Fprintf(&b, "%s %d/100 (%s)   %s\n", paint(bold, "Score"), r.Score, r.Grade, strings.Join(parts, " · "))
	meta := fmt.Sprintf("%d checks · %d skipped · %d errors · %d suppressed · %dms",
		r.ChecksRun, len(r.Skipped), len(r.Errors), r.Suppressed, r.DurationMS)
	b.WriteString(paint(dim, meta) + "\n")
	for _, e := range r.Errors {
		fmt.Fprintf(&b, "%s\n", paint(dim, fmt.Sprintf("error %s: %s", e.CheckID, e.Reason)))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func pad(s string, n int) string {
	if c := utf8.RuneCountInString(s); c < n {
		return s + strings.Repeat(" ", n-c)
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown OS"
	}
	return s
}
