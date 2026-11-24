package compromise

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

func runPreload(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	var out []audit.Finding
	if lines, err := h.Lines("/etc/ld.so.preload"); err == nil {
		for _, l := range lines {
			lib := strings.TrimSpace(l.Text)
			if lib == "" || strings.HasPrefix(lib, "#") {
				continue
			}
			out = append(out, audit.Finding{
				Target:   fmt.Sprintf("/etc/ld.so.preload:%d", l.N),
				Message:  fmt.Sprintf("library %s is preloaded into every dynamically linked process", lib),
				Evidence: []string{lib},
				Fix: fmt.Sprintf("# Userland rootkits (libprocesshider, Kinsing) hide via ld.so.preload. Capture first:\ncp -a %s /root/ir-evidence/ 2>/dev/null; sha256sum %s\n# then: rm /etc/ld.so.preload",
					audit.ShellQuote(lib), audit.ShellQuote(lib)),
			})
		}
	}
	if lines, err := h.Lines("/etc/environment"); err == nil {
		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l.Text), "LD_PRELOAD") {
				out = append(out, audit.Finding{
					Target:   fmt.Sprintf("/etc/environment:%d", l.N),
					Severity: audit.High,
					Message:  "LD_PRELOAD set globally in /etc/environment",
					Evidence: []string{strings.TrimSpace(l.Text)},
				})
			}
		}
	}
	return out, nil
}

// cronSources lists crontab locations: system crontabs carry a user field,
// per-user spools do not.
func cronSources(h *host.Host) (system, user []string) {
	system = append(system, h.Glob("/etc/crontab")...)
	system = append(system, h.Glob("/etc/cron.d/*")...)
	user = append(user, h.Glob("/var/spool/cron/crontabs/*")...)
	for _, p := range h.Glob("/var/spool/cron/*") {
		if fi, err := h.Lstat(p); err == nil && fi.Mode().IsRegular() {
			user = append(user, p) // RHEL layout
		}
	}
	return system, user
}

func runCron(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	system, user := cronSources(h)
	var out []audit.Finding
	scan := func(file string, hasUserField bool) {
		lines, err := h.Lines(file)
		if err != nil {
			return
		}
		for _, l := range lines {
			cmd := cronCommand(l.Text, hasUserField)
			if cmd == "" {
				continue
			}
			if reasons := suspiciousReasons(cmd); len(reasons) > 0 {
				out = append(out, persistenceFinding(file, l, reasons))
			}
		}
	}
	for _, f := range system {
		scan(f, true)
	}
	for _, f := range user {
		scan(f, false)
	}
	// Scripts dropped into the periodic directories run as root.
	for _, dir := range []string{"hourly", "daily", "weekly", "monthly"} {
		for _, f := range h.Glob("/etc/cron." + dir + "/*") {
			lines, err := h.Lines(f)
			if err != nil {
				continue
			}
			for _, l := range lines {
				t := strings.TrimSpace(l.Text)
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				if reasons := suspiciousReasons(t); len(reasons) > 0 {
					out = append(out, persistenceFinding(f, l, reasons))
				}
			}
		}
	}
	return out, nil
}

// cronCommand strips the schedule (and user field) from a crontab line and
// returns the command, or "" for comments, blanks and variable assignments.
func cronCommand(line string, hasUserField bool) string {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	f := strings.Fields(t)
	skip := 5
	if strings.HasPrefix(f[0], "@") {
		skip = 1
	} else if strings.Contains(f[0], "=") {
		return ""
	}
	if hasUserField {
		skip++
	}
	if len(f) <= skip {
		return ""
	}
	return strings.Join(f[skip:], " ")
}

func persistenceFinding(file string, l host.Line, reasons []string) audit.Finding {
	return audit.Finding{
		Target:   fmt.Sprintf("%s:%d", file, l.N),
		Message:  fmt.Sprintf("%s: %s", file, strings.Join(reasons, "; ")),
		Evidence: []string{strings.TrimSpace(l.Text)},
		Fix: fmt.Sprintf("# Preserve evidence, then remove the entry:\ncp -a %[1]s /root/ir-evidence/ 2>/dev/null\nsed -i '%[2]dd' %[1]s",
			audit.ShellQuote(file), l.N),
	}
}

var unitDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/usr/local/lib/systemd/system"}

func runSystemd(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	var files []string
	for _, d := range unitDirs {
		if fi, err := h.Lstat(d); err != nil || !fi.IsDir() {
			continue // skip /lib when it is a usrmerge symlink to avoid duplicates
		}
		for _, ext := range []string{"*.service", "*.timer", "*.service.d/*.conf"} {
			files = append(files, h.Glob(path.Join(d, ext))...)
		}
	}
	for _, home := range h.HomeDirs() {
		files = append(files, h.Glob(path.Join(home, ".config/systemd/user/*.service"))...)
	}
	var out []audit.Finding
	for _, f := range files {
		lines, err := h.Lines(f)
		if err != nil {
			continue
		}
		for _, l := range lines {
			key, val, ok := strings.Cut(strings.TrimSpace(l.Text), "=")
			if !ok || !strings.HasPrefix(key, "Exec") {
				continue
			}
			cmd := strings.TrimLeft(strings.TrimSpace(val), "-@+!:")
			if reasons := suspiciousReasons(cmd); len(reasons) > 0 {
				fd := persistenceFinding(f, l, reasons)
				unit := path.Base(f)
				fd.Fix = fmt.Sprintf("systemctl stop %[1]s; systemctl disable %[1]s\ncp -a %[2]s /root/ir-evidence/ 2>/dev/null; rm %[2]s; systemctl daemon-reload",
					audit.ShellQuote(unit), audit.ShellQuote(f))
				out = append(out, fd)
			}
		}
	}
	return out, nil
}

var initScripts = []string{"/etc/rc.local", "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"}

func runInitScripts(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	files := append([]string{}, initScripts...)
	files = append(files, h.Glob("/etc/profile.d/*.sh")...)
	files = append(files, h.Glob("/etc/init.d/*")...)
	for _, home := range h.HomeDirs() {
		for _, rc := range []string{".bashrc", ".profile", ".bash_profile", ".zshrc"} {
			files = append(files, path.Join(home, rc))
		}
	}
	var out []audit.Finding
	for _, f := range files {
		lines, err := h.Lines(f)
		if err != nil {
			continue
		}
		for _, l := range lines {
			t := strings.TrimSpace(l.Text)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if reasons := suspiciousReasons(t); len(reasons) > 0 {
				out = append(out, persistenceFinding(f, l, reasons))
			}
		}
	}
	return out, nil
}
