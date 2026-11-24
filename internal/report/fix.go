package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

// FixScript writes a reviewable remediation script for the active findings.
// hostwarden never executes it; every block is guarded so that a reviewer
// must opt in explicitly by running the script themselves.
func FixScript(w io.Writer, r *audit.Report) error {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	fmt.Fprintf(&b, "# hostwarden %s remediation plan for %s (%s)\n", r.Version, r.Host.Hostname, r.StartedAt.Format("2006-01-02T15:04:05Z"))
	b.WriteString("# Generated, NOT executed. Review every step: some fixes can lock you out\n")
	b.WriteString("# (SSH changes) or destroy evidence (killing processes). Lines that would\n")
	b.WriteString("# destroy forensic state are commented out on purpose.\n")
	b.WriteString("set -euo pipefail\n")
	b.WriteString("mkdir -p /root/ir-evidence\n")
	active := r.Active()
	if len(active) == 0 {
		b.WriteString("\n# No active findings. Nothing to do.\n")
	}
	for _, f := range active {
		fmt.Fprintf(&b, "\n# [%s] %s %s\n# target: %s\n# %s\n",
			strings.ToUpper(f.Severity.String()), f.CheckID, f.Title, f.Target, oneLine(f.Message))
		fix := strings.TrimSpace(f.Fix)
		if fix == "" {
			fmt.Fprintf(&b, "# Manual remediation: %s\n", oneLine(f.Remediation))
			continue
		}
		b.WriteString(fix + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
