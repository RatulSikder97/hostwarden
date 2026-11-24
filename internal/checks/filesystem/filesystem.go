// Package filesystem audits permissions, setuid binaries, mounts and key exposure.
package filesystem

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

// Checks returns the filesystem checks.
func Checks() []audit.Check {
	return []audit.Check{
		{
			ID:          "HW-FS-001",
			Title:       "World-writable directory without sticky bit",
			Category:    audit.CategoryFilesystem,
			Severity:    audit.Medium,
			Rationale:   "Without the sticky bit any user can delete or replace other users' files, enabling binary planting and symlink attacks.",
			Remediation: "Set the sticky bit (`chmod +t`) or remove world write permission.",
			Run:         runWorldWritable,
		},
		{
			ID:       "HW-FS-002",
			Title:    "Unexpected setuid/setgid binary",
			Category: audit.CategoryFilesystem,
			Severity: audit.High,
			Rationale: "Setuid binaries run with their owner's privileges. Attackers drop setuid copies of shells in /tmp or home " +
				"directories to keep root after the initial exploit is patched.",
			Remediation: "Verify the binary belongs to a package (`dpkg -S` / `rpm -qf`); remove the setuid bit or the file if not.",
			Run:         runSetID,
		},
		{
			ID:          "HW-FS-003",
			Title:       "Temporary filesystem allows execution",
			Category:    audit.CategoryFilesystem,
			Severity:    audit.Low,
			Rationale:   "Droppers almost always stage payloads in /tmp, /var/tmp or /dev/shm. Mounting them noexec breaks most commodity malware chains.",
			Remediation: "Mount /tmp and /dev/shm with nodev,nosuid,noexec (e.g. via /etc/fstab or tmp.mount).",
			Run:         runTmpMounts,
		},
		{
			ID:          "HW-FS-004",
			Title:       "Sensitive account file has unsafe permissions",
			Category:    audit.CategoryFilesystem,
			Severity:    audit.High,
			Rationale:   "/etc/shadow holds password hashes; if readable by others they can be cracked offline. Writable passwd/group/sudoers grants root.",
			Remediation: "chmod 640 /etc/shadow /etc/gshadow; chmod 644 /etc/passwd /etc/group; chmod 440 /etc/sudoers.",
			Run:         runSensitivePerms,
		},
		{
			ID:          "HW-FS-005",
			Title:       "Private key readable by other users",
			Category:    audit.CategoryFilesystem,
			Severity:    audit.High,
			Rationale:   "Readable SSH host keys, user identity keys and TLS keys let any local user (or a compromised service) impersonate the host or pivot to other systems.",
			Remediation: "chmod 600 the key file and make sure its directory is not world-readable.",
			Run:         runPrivateKeys,
		},
	}
}

func runWorldWritable(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	scan, err := h.Files()
	if err != nil {
		return nil, err
	}
	out := make([]audit.Finding, 0, len(scan.WorldWritableDirs))
	for _, e := range scan.WorldWritableDirs {
		out = append(out, audit.Finding{
			Target:  e.Path,
			Message: fmt.Sprintf("%s is world-writable without the sticky bit (%s)", e.Path, e.Mode),
			Fix:     "chmod +t " + audit.ShellQuote(e.Path),
		})
	}
	return out, nil
}

// knownSetID are setuid/setgid binaries shipped by mainstream distributions.
var knownSetID = map[string]bool{
	"passwd": true, "chsh": true, "chfn": true, "gpasswd": true, "newgrp": true, "su": true, "sudo": true,
	"mount": true, "umount": true, "ping": true, "ping6": true, "pkexec": true, "crontab": true,
	"ssh-keysign": true, "dbus-daemon-launch-helper": true, "fusermount": true, "fusermount3": true,
	"unix_chkpwd": true, "pam_timestamp_check": true, "chage": true, "expiry": true, "wall": true,
	"write": true, "at": true, "newuidmap": true, "newgidmap": true, "polkit-agent-helper-1": true,
	"Xorg.wrap": true, "snap-confine": true, "sg": true, "staprun": true, "utempter": true,
	"ssh-agent": true, "bsd-write": true, "mlocate": true, "plocate": true, "dotlockfile": true,
	"chrome-sandbox": true, "pt_chown": true, "userhelper": true, "usernetctl": true, "grub2-set-bootflag": true,
	"locate": true, "lockdev": true, "mount.nfs": true, "mount.cifs": true, "netreport": true, "postdrop": true, "postqueue": true,
}

var systemBinDirs = []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/", "/usr/lib64/", "/lib64/"}

var stagingDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/home/", "/root/"}

func runSetID(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	scan, err := h.Files()
	if err != nil {
		return nil, err
	}
	var out []audit.Finding
	for _, e := range scan.SetID {
		name := path.Base(e.Path)
		inSystem := hasAnyPrefix(e.Path, systemBinDirs)
		if inSystem && knownSetID[name] {
			continue
		}
		sev := audit.High
		reason := "not on the list of distribution setuid/setgid binaries"
		if hasAnyPrefix(e.Path, stagingDirs) {
			sev = audit.Critical
			reason = "setuid/setgid binary in a user-writable location (classic root persistence)"
		} else if !inSystem {
			reason = "setuid/setgid binary outside system binary directories"
		}
		out = append(out, audit.Finding{
			Target:   e.Path,
			Severity: sev,
			Message:  fmt.Sprintf("%s (%s): %s", e.Path, e.Mode, reason),
			Fix:      fmt.Sprintf("dpkg -S %[1]s 2>/dev/null || rpm -qf %[1]s 2>/dev/null || chmod u-s,g-s %[1]s", audit.ShellQuote(e.Path)),
		})
	}
	return out, nil
}

func runTmpMounts(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	mounts, err := h.Mounts()
	if err != nil {
		return nil, audit.Skip("procfs mounts unavailable")
	}
	byPoint := map[string]host.MountEntry{}
	for _, m := range mounts {
		byPoint[m.Point] = m // last mount at a point wins, as in the kernel
	}
	var out []audit.Finding
	for _, p := range []string{"/tmp", "/dev/shm"} {
		m, ok := byPoint[p]
		if !ok {
			if p == "/tmp" && h.Exists(p) {
				out = append(out, audit.Finding{
					Target:  p,
					Message: "/tmp is not a separate mount, so noexec/nosuid cannot be enforced",
					Fix:     "systemctl enable --now tmp.mount  # or add a tmpfs /tmp line with nodev,nosuid,noexec to /etc/fstab",
				})
			}
			continue
		}
		var missing []string
		for _, opt := range []string{"noexec", "nosuid", "nodev"} {
			if !m.HasOption(opt) {
				missing = append(missing, opt)
			}
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, audit.Finding{
			Target:   p,
			Message:  fmt.Sprintf("%s is mounted without %s", p, strings.Join(missing, ",")),
			Evidence: []string{fmt.Sprintf("%s %s %s %s", m.Device, m.Point, m.FSType, strings.Join(m.Options, ","))},
			Fix:      fmt.Sprintf("mount -o remount,%s %s  # persist in /etc/fstab", strings.Join(missing, ","), p),
		})
	}
	return out, nil
}

// sensitiveFiles maps paths to the permission bits that must not be set.
var sensitiveFiles = []struct {
	Path      string
	Forbidden fs.FileMode
	Want      string
}{
	{"/etc/shadow", 0o037, "640"},
	{"/etc/gshadow", 0o037, "640"},
	{"/etc/passwd", 0o022, "644"},
	{"/etc/group", 0o022, "644"},
	{"/etc/sudoers", 0o037, "440"},
	{"/etc/ssh/sshd_config", 0o022, "600"},
	{"/etc/crontab", 0o022, "600"},
}

func runSensitivePerms(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	var out []audit.Finding
	for _, sf := range sensitiveFiles {
		fi, err := h.Lstat(sf.Path)
		if err != nil {
			continue
		}
		perm := fi.Mode().Perm()
		if perm&sf.Forbidden == 0 {
			continue
		}
		sev := audit.High
		if perm&0o002 != 0 || (sf.Path == "/etc/shadow" || sf.Path == "/etc/gshadow") && perm&0o004 != 0 {
			sev = audit.Critical
		}
		out = append(out, audit.Finding{
			Target:   sf.Path,
			Severity: sev,
			Message:  fmt.Sprintf("%s has mode %04o", sf.Path, perm),
			Fix:      fmt.Sprintf("chmod %s %s", sf.Want, sf.Path),
		})
	}
	return out, nil
}

func runPrivateKeys(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	scan, err := h.Files()
	if err != nil {
		return nil, err
	}
	out := make([]audit.Finding, 0, len(scan.ExposedPrivateKeys))
	for _, e := range scan.ExposedPrivateKeys {
		sev := audit.High
		if e.Mode.Perm()&0o004 != 0 {
			sev = audit.Critical
		}
		out = append(out, audit.Finding{
			Target:   e.Path,
			Severity: sev,
			Message:  fmt.Sprintf("private key %s is readable by group/others (mode %04o)", e.Path, e.Mode.Perm()),
			Fix:      "chmod 600 " + audit.ShellQuote(e.Path),
		})
	}
	return out, nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
