// Package accounts audits local accounts and privilege grants.
package accounts

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

// Checks returns the account and privilege checks.
func Checks() []audit.Check {
	return []audit.Check{
		{
			ID:          "HW-ACC-001",
			Title:       "Additional account with UID 0",
			Category:    audit.CategoryAccounts,
			Severity:    audit.Critical,
			Rationale:   "Any account with UID 0 is root. Extra UID 0 accounts (\"toor\", \"admin\") are a classic backdoor that survives root password changes.",
			Remediation: "Remove the account or assign it a unique non-zero UID after confirming it is not legitimately required.",
			Run:         runDuplicateRoot,
		},
		{
			ID:          "HW-ACC-002",
			Title:       "Account with an empty password",
			Category:    audit.CategoryAccounts,
			Severity:    audit.Critical,
			Rationale:   "An empty password hash allows login without any credential on every PAM service that permits it.",
			Remediation: "Lock the account (`passwd -l <user>`) or set a strong password.",
			Run:         runEmptyPasswords,
		},
		{
			ID:          "HW-ACC-003",
			Title:       "Passwordless sudo grant",
			Category:    audit.CategoryAccounts,
			Severity:    audit.Medium,
			Rationale:   "NOPASSWD rules turn any compromise of the grantee (a leaked key, an RCE in a service running as that user) into root without further effort.",
			Remediation: "Remove NOPASSWD or scope it to specific, non-shell-escaping commands. Validate with `visudo -c`.",
			Run:         runSudoers,
		},
		{
			ID:          "HW-ACC-004",
			Title:       "System account has an interactive shell",
			Category:    audit.CategoryAccounts,
			Severity:    audit.Low,
			Rationale:   "Service accounts should not be able to log in. An interactive shell makes a compromised daemon account a usable foothold.",
			Remediation: "Set the shell to /usr/sbin/nologin: `usermod -s /usr/sbin/nologin <user>`.",
			Run:         runSystemShells,
		},
	}
}

func runDuplicateRoot(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	users, err := h.Users()
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd: %w", err)
	}
	var out []audit.Finding
	for _, u := range users {
		if u.UID == 0 && u.Name != "root" {
			out = append(out, audit.Finding{
				Target:   "user:" + u.Name,
				Message:  fmt.Sprintf("account %q has UID 0", u.Name),
				Evidence: []string{fmt.Sprintf("/etc/passwd:%d", u.Line)},
				Fix:      fmt.Sprintf("# Investigate first: last -F %[1]s; grep %[1]s /var/log/auth.log*\nuserdel %[1]s", u.Name),
			})
		}
	}
	return out, nil
}

func runEmptyPasswords(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	users, err := h.Users()
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd: %w", err)
	}
	var out []audit.Finding
	empty := map[string]string{}
	for _, u := range users {
		if u.Passwd == "" {
			empty[u.Name] = fmt.Sprintf("/etc/passwd:%d", u.Line)
		}
	}
	if shadow, err := h.Shadow(); err == nil {
		for _, s := range shadow {
			if s.Hash == "" {
				empty[s.Name] = fmt.Sprintf("/etc/shadow:%d", s.Line)
			}
		}
	}
	for _, u := range users {
		src, ok := empty[u.Name]
		if !ok {
			continue
		}
		out = append(out, audit.Finding{
			Target:   "user:" + u.Name,
			Message:  fmt.Sprintf("account %q has an empty password field", u.Name),
			Evidence: []string{src},
			Fix:      "passwd -l " + u.Name,
		})
	}
	return out, nil
}

var nopasswdAll = regexp.MustCompile(`NOPASSWD\s*:\s*ALL\s*$`)

func runSudoers(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	files := []string{"/etc/sudoers"}
	files = append(files, h.Glob("/etc/sudoers.d/*")...)
	seen := map[string]bool{}
	var out []audit.Finding
	for len(files) > 0 {
		f := files[0]
		files = files[1:]
		if seen[f] {
			continue
		}
		seen[f] = true
		lines, err := h.Lines(f)
		if err != nil {
			continue
		}
		for _, l := range lines {
			text := strings.TrimSpace(l.Text)
			if dir, ok := includeDirective(text, "includedir"); ok {
				files = append(files, h.Glob(path.Join(dir, "*"))...)
				continue
			}
			if inc, ok := includeDirective(text, "include"); ok {
				if !path.IsAbs(inc) {
					inc = path.Join(path.Dir(f), inc)
				}
				files = append(files, inc)
				continue
			}
			if text == "" || strings.HasPrefix(text, "#") || !strings.Contains(text, "NOPASSWD") {
				continue
			}
			sev := audit.Medium
			msg := "passwordless sudo for specific commands"
			if nopasswdAll.MatchString(text) {
				sev = audit.High
				msg = "passwordless sudo for ALL commands (root-equivalent)"
			}
			target := fmt.Sprintf("%s:%d", f, l.N)
			out = append(out, audit.Finding{
				Target:   target,
				Severity: sev,
				Message:  fmt.Sprintf("%s: %s", strings.Fields(text)[0], msg),
				Evidence: []string{text},
				Fix:      fmt.Sprintf("# Edit with: visudo -f %s  (remove NOPASSWD on line %d)", f, l.N),
			})
		}
	}
	return out, nil
}

// includeDirective parses "#includedir X" / "@includedir X" (and include).
func includeDirective(line, name string) (string, bool) {
	for _, prefix := range []string{"#" + name + " ", "@" + name + " "} {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

var nonInteractive = []string{"nologin", "false", "sync", "shutdown", "halt", "true"}

func runSystemShells(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	users, err := h.Users()
	if err != nil {
		return nil, fmt.Errorf("read /etc/passwd: %w", err)
	}
	uidMin := loginDefsUIDMin(h)
	var out []audit.Finding
	for _, u := range users {
		if u.UID == 0 || u.UID >= uidMin || u.UID == 65534 {
			continue
		}
		base := path.Base(u.Shell)
		if u.Shell == "" || isNonInteractive(base) {
			continue
		}
		out = append(out, audit.Finding{
			Target:   "user:" + u.Name,
			Message:  fmt.Sprintf("system account %q (uid %d) has shell %s", u.Name, u.UID, u.Shell),
			Evidence: []string{fmt.Sprintf("/etc/passwd:%d", u.Line)},
			Fix:      "usermod -s /usr/sbin/nologin " + u.Name,
		})
	}
	return out, nil
}

func isNonInteractive(shell string) bool { return slices.Contains(nonInteractive, shell) }

func loginDefsUIDMin(h *host.Host) int {
	lines, err := h.Lines("/etc/login.defs")
	if err == nil {
		for _, l := range lines {
			f := strings.Fields(l.Text)
			if len(f) == 2 && f[0] == "UID_MIN" {
				var v int
				if _, err := fmt.Sscanf(f[1], "%d", &v); err == nil && v > 0 {
					return v
				}
			}
		}
	}
	return 1000
}
