// Package kernel audits sysctl hardening and patch hygiene.
package kernel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

// Checks returns kernel and maintenance checks.
func Checks() []audit.Check {
	return []audit.Check{
		{
			ID:          "HW-KRN-001",
			Title:       "Kernel sysctl not hardened",
			Category:    audit.CategoryKernel,
			Severity:    audit.Low,
			Rationale:   "Kernel defaults favour compatibility. ASLR, pointer/dmesg restrictions, link protections and ICMP redirect handling reduce local privilege escalation and network attack surface (CIS 1.5, 3.2, 3.3).",
			Remediation: "Persist the expected values in /etc/sysctl.d/99-hardening.conf and run `sysctl --system`.",
			Run:         runSysctl,
		},
		{
			ID:          "HW-KRN-002",
			Title:       "Automatic security updates not enabled",
			Category:    audit.CategoryMaintenance,
			Severity:    audit.Low,
			Rationale:   "Most mass-exploited vulnerabilities have patches available for weeks before exploitation; unattended updates close that window.",
			Remediation: "Debian/Ubuntu: install and enable unattended-upgrades. RHEL family: enable dnf-automatic with `apply_updates = yes`.",
			Run:         runAutoUpdates,
		},
		{
			ID:          "HW-KRN-003",
			Title:       "Pending security updates",
			Category:    audit.CategoryMaintenance,
			Severity:    audit.Medium,
			Rationale:   "Installed packages with published security fixes are known-vulnerable.",
			Remediation: "Apply updates (`apt-get upgrade` / `dnf upgrade --security`) and reboot if the kernel changed.",
			Run:         runPendingUpdates,
		},
		{
			ID:          "HW-KRN-004",
			Title:       "Reboot required to activate updates",
			Category:    audit.CategoryMaintenance,
			Severity:    audit.Low,
			Rationale:   "Kernel and libc fixes are not effective until the host reboots or services restart.",
			Remediation: "Schedule a reboot (or use livepatch for the kernel).",
			Run:         runRebootRequired,
		},
	}
}

type sysctlRule struct {
	Key      string
	Want     string
	OK       func(int) bool
	Severity audit.Severity
}

func atLeast(n int) func(int) bool { return func(v int) bool { return v >= n } }
func equals(n int) func(int) bool  { return func(v int) bool { return v == n } }

// SysctlRules is the sysctl baseline hostwarden enforces.
var SysctlRules = []sysctlRule{
	{"kernel.randomize_va_space", "2", equals(2), audit.Medium},
	{"kernel.kptr_restrict", ">=1", atLeast(1), audit.Low},
	{"kernel.dmesg_restrict", "1", equals(1), audit.Low},
	{"kernel.yama.ptrace_scope", ">=1", atLeast(1), audit.Low},
	{"kernel.unprivileged_bpf_disabled", ">=1", atLeast(1), audit.Low},
	{"fs.protected_symlinks", "1", equals(1), audit.Medium},
	{"fs.protected_hardlinks", "1", equals(1), audit.Medium},
	{"fs.suid_dumpable", "0", equals(0), audit.Low},
	{"net.ipv4.tcp_syncookies", "1", equals(1), audit.Low},
	{"net.ipv4.conf.all.accept_redirects", "0", equals(0), audit.Low},
	{"net.ipv4.conf.all.send_redirects", "0", equals(0), audit.Low},
	{"net.ipv4.conf.all.accept_source_route", "0", equals(0), audit.Low},
	{"net.ipv4.conf.all.log_martians", "1", equals(1), audit.Low},
}

func runSysctl(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	var out []audit.Finding
	read := 0
	for _, r := range SysctlRules {
		raw, err := h.ReadSysctl(r.Key)
		if err != nil {
			continue
		}
		read++
		v, err := strconv.Atoi(raw)
		if err != nil || r.OK(v) {
			continue
		}
		want := strings.TrimPrefix(r.Want, ">=")
		out = append(out, audit.Finding{
			Target:   r.Key,
			Severity: r.Severity,
			Message:  fmt.Sprintf("%s = %s (expected %s)", r.Key, raw, r.Want),
			Fix: fmt.Sprintf("echo '%s = %s' >> /etc/sysctl.d/99-hardening.conf && sysctl -w %s=%s",
				r.Key, want, r.Key, want),
		})
	}
	if read == 0 {
		return nil, audit.Skip("no sysctls readable under %s", h.ProcPath("sys"))
	}
	return out, nil
}

var (
	aptPeriodic = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"(\d+)"`)
	dnfApply    = regexp.MustCompile(`(?m)^\s*apply_updates\s*=\s*(yes|true|1)`)
)

func runAutoUpdates(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	switch h.OSFamily() {
	case "debian":
		enabled := false
		for _, f := range h.Glob("/etc/apt/apt.conf.d/*") {
			b, err := h.ReadFile(f)
			if err != nil {
				continue
			}
			for _, m := range aptPeriodic.FindAllSubmatch(b, -1) {
				enabled = string(m[1]) != "0"
			}
		}
		if enabled && h.Exists("/usr/bin/unattended-upgrade") {
			return nil, nil
		}
		return []audit.Finding{{
			Target:  "unattended-upgrades",
			Message: "unattended-upgrades is not installed or APT::Periodic::Unattended-Upgrade is not enabled",
			Fix:     "apt-get install -y unattended-upgrades && dpkg-reconfigure -f noninteractive unattended-upgrades",
		}}, nil
	case "rhel":
		b, err := h.ReadFile("/etc/dnf/automatic.conf")
		timer := len(h.Glob("/etc/systemd/system/timers.target.wants/dnf-automatic*.timer")) > 0
		if err == nil && timer && dnfApply.Match(b) {
			return nil, nil
		}
		return []audit.Finding{{
			Target:  "dnf-automatic",
			Message: "dnf-automatic is not configured to apply updates",
			Fix:     "dnf install -y dnf-automatic && sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf && systemctl enable --now dnf-automatic.timer",
		}}, nil
	default:
		return nil, audit.Skip("unsupported distribution for update checks")
	}
}

var notifierSecurity = regexp.MustCompile(`(\d+)\s+(?:of these )?updates? (?:are|is a) (?:standard )?security updates?`)

func runPendingUpdates(ctx context.Context, h *host.Host) ([]audit.Finding, error) {
	// Ubuntu's update-notifier caches counts in a plain file; prefer it.
	if b, err := h.ReadFile("/var/lib/update-notifier/updates-available"); err == nil {
		if m := notifierSecurity.FindSubmatch(b); m != nil {
			n, _ := strconv.Atoi(string(m[1]))
			if n == 0 {
				return nil, nil
			}
			return []audit.Finding{pendingFinding(n, nil, "/var/lib/update-notifier/updates-available")}, nil
		}
	}
	// The CLI only wires an Executor when auditing the live root ("/").
	if h.Exec == nil {
		return nil, audit.Skip("package manager probes disabled (offline root or --no-exec)")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	switch h.OSFamily() {
	case "debian":
		// -s simulates: nothing is downloaded or installed, no lock is taken.
		b, err := h.Exec.Output(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
		if err != nil {
			return nil, audit.Skip("apt-get simulation failed: %v", err)
		}
		pkgs := aptSecurityUpgrades(b)
		if len(pkgs) == 0 {
			return nil, nil
		}
		return []audit.Finding{pendingFinding(len(pkgs), pkgs, "apt-get -s upgrade")}, nil
	case "rhel":
		b, err := h.Exec.Output(ctx, "dnf", "-q", "--cacheonly", "updateinfo", "list", "--security")
		if err != nil {
			return nil, audit.Skip("dnf updateinfo failed: %v", err)
		}
		var pkgs []string
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			if f := strings.Fields(sc.Text()); len(f) >= 3 {
				pkgs = append(pkgs, f[2])
			}
		}
		if len(pkgs) == 0 {
			return nil, nil
		}
		return []audit.Finding{pendingFinding(len(pkgs), pkgs, "dnf updateinfo list --security")}, nil
	default:
		return nil, audit.Skip("unsupported distribution for update checks")
	}
}

// aptSecurityUpgrades extracts package names from `apt-get -s upgrade` lines
// such as "Inst openssl [3.0.11-1] (3.0.13-1 Debian-Security:12/stable-security [amd64])".
func aptSecurityUpgrades(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Inst ") || !strings.Contains(strings.ToLower(line), "security") {
			continue
		}
		if f := strings.Fields(line); len(f) > 1 {
			out = append(out, f[1])
		}
	}
	return out
}

func pendingFinding(n int, pkgs []string, source string) audit.Finding {
	ev := []string{"source: " + source}
	if len(pkgs) > 20 {
		ev = append(ev, strings.Join(pkgs[:20], " ")+fmt.Sprintf(" ... (+%d)", len(pkgs)-20))
	} else if len(pkgs) > 0 {
		ev = append(ev, strings.Join(pkgs, " "))
	}
	return audit.Finding{
		Target:   "packages",
		Message:  fmt.Sprintf("%d security update(s) pending", n),
		Evidence: ev,
		Fix:      "apt-get update && apt-get upgrade -y  # or: dnf upgrade --security -y",
	}
}

func runRebootRequired(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	if !h.Exists("/run/reboot-required") {
		return nil, nil
	}
	var ev []string
	if lines, err := h.Lines("/run/reboot-required.pkgs"); err == nil {
		for _, l := range lines {
			ev = append(ev, l.Text)
		}
	}
	return []audit.Finding{{
		Target:   "/run/reboot-required",
		Message:  "packages updated since last boot require a reboot",
		Evidence: ev,
		Fix:      "# Schedule a maintenance window:\nshutdown -r +5 'hostwarden: applying security updates'",
	}}, nil
}
