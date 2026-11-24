package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/RatulSikder97/hostwarden/internal/checks"
)

func runChecks(_ context.Context, args []string, streams IO) int {
	fs := flag.NewFlagSet("checks", flag.ContinueOnError)
	fs.SetOutput(streams.Stderr)
	format := fs.String("format", "table", "output format: table, markdown or json")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	all := checks.All()
	switch *format {
	case "json":
		type entry struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			Category    string `json:"category"`
			Severity    string `json:"severity"`
			Rationale   string `json:"rationale"`
			Remediation string `json:"remediation"`
		}
		out := make([]entry, 0, len(all))
		for _, c := range all {
			out = append(out, entry{c.ID, c.Title, string(c.Category), c.Severity.String(), c.Rationale, c.Remediation})
		}
		enc := json.NewEncoder(streams.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return errorf(streams.Stderr, "%v", err)
		}
	case "markdown":
		var b strings.Builder
		b.WriteString("| ID | Severity | Category | What it detects |\n|---|---|---|---|\n")
		for _, c := range all {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", c.ID, c.Severity, c.Category, c.Title)
		}
		fmt.Fprint(streams.Stdout, b.String())
	case "table":
		tw := tabwriter.NewWriter(streams.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tTITLE")
		for _, c := range all {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID, c.Severity, c.Category, c.Title)
		}
		if err := tw.Flush(); err != nil {
			return errorf(streams.Stderr, "%v", err)
		}
	default:
		return errorf(streams.Stderr, "--format must be table, markdown or json")
	}
	return ExitOK
}
