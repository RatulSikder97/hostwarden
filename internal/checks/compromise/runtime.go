package compromise

import (
	"context"
	"crypto/md5" //nolint:gosec // dpkg md5sums manifests use MD5; this is integrity comparison, not security.
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	xssh "golang.org/x/crypto/ssh"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

var stagingPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/"}

var systemPrefixes = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/"}

func hasPrefixAny(s string, ps []string) bool {
	return slices.ContainsFunc(ps, func(p string) bool { return strings.HasPrefix(s, p) })
}

// hiddenPath reports whether any path component starts with a dot.
func hiddenPath(p string) bool {
	for c := range strings.SplitSeq(p, "/") {
		if len(c) > 1 && c[0] == '.' && c != ".." {
			return true
		}
	}
	return false
}

func processes(h *host.Host) ([]host.Process, error) {
	procs, err := h.Processes()
	if err != nil {
		if host.IsNotExist(err) {
			return nil, audit.Skip("procfs unavailable at %s", h.Proc)
		}
		return nil, err
	}
	return procs, nil
}

func procTarget(p host.Process) string { return fmt.Sprintf("pid:%d", p.PID) }

func procEvidence(p host.Process) []string {
	ev := []string{fmt.Sprintf("exe=%s", p.Exe), fmt.Sprintf("cmdline=%s", p.CommandLine())}
	if p.UID >= 0 {
		ev = append(ev, fmt.Sprintf("uid=%d ppid=%d cpu=%.1f%%", p.UID, p.PPID, p.CPUPercent))
	}
	return ev
}

func killFix(p host.Process) string {
	return fmt.Sprintf(`# Capture before killing (the binary may only exist in memory):
cp /proc/%[1]d/exe /root/ir-evidence/pid-%[1]d.bin 2>/dev/null; cat /proc/%[1]d/cmdline | tr '\0' ' '; ls -l /proc/%[1]d/fd
# kill -9 %[1]d`, p.PID)
}

func runDeletedExe(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	procs, err := processes(h)
	if err != nil {
		return nil, err
	}
	var out []audit.Finding
	for _, p := range procs {
		if !p.ExeDeleted() {
			continue
		}
		exe := p.ExePath()
		sev := audit.High
		msg := fmt.Sprintf("%s (pid %d) runs from a deleted binary %s", p.Comm, p.PID, exe)
		switch {
		case strings.HasPrefix(exe, "/memfd:"):
			sev = audit.Critical
			msg = fmt.Sprintf("%s (pid %d) runs from an anonymous memfd (fileless execution)", p.Comm, p.PID)
		case hasPrefixAny(exe, systemPrefixes) && !hiddenPath(exe):
			sev = audit.Low
			msg += " (likely upgraded package awaiting restart)"
		}
		out = append(out, audit.Finding{
			Target: procTarget(p), Severity: sev, Message: msg, Evidence: procEvidence(p), Fix: killFix(p),
		})
	}
	return out, nil
}

func runStagingExe(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	procs, err := processes(h)
	if err != nil {
		return nil, err
	}
	var out []audit.Finding
	for _, p := range procs {
		exe := p.ExePath()
		if exe == "" || !hasPrefixAny(exe, stagingPrefixes) {
			continue
		}
		out = append(out, audit.Finding{
			Target:   procTarget(p),
			Message:  fmt.Sprintf("%s (pid %d) executes from world-writable location %s", p.Comm, p.PID, path.Dir(exe)),
			Evidence: procEvidence(p),
			Fix:      killFix(p),
		})
	}
	return out, nil
}

// PoolPorts are TCP ports conventionally used by stratum mining pools.
var PoolPorts = map[uint16]bool{
	3333: true, 3357: true, 4444: true, 5555: true, 6666: true, 7777: true, 10128: true,
	10343: true, 14433: true, 14444: true, 17777: true, 20535: true, 45560: true, 45700: true,
}

// highCPU is the lifetime-average CPU percentage above which an otherwise
// suspicious process is treated as a probable miner.
const highCPU = 80.0

func runMiners(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	procs, err := processes(h)
	if err != nil {
		return nil, err
	}
	poolConns := map[int][]string{}
	if socks, err := h.Sockets(); err == nil {
		owners := h.SocketOwners()
		for _, s := range socks {
			if s.State == host.StateEstablished && PoolPorts[s.Remote.Port()] {
				if p, ok := owners[s.Inode]; ok {
					poolConns[p.PID] = append(poolConns[p.PID], s.Remote.String())
				}
			}
		}
	}
	var out []audit.Finding
	for _, p := range procs {
		var strong, weak []string
		names := p.Comm + " " + path.Base(p.ExePath())
		if len(p.Cmdline) > 0 {
			names += " " + path.Base(p.Cmdline[0])
		}
		if minerNameRe.MatchString(names) {
			strong = append(strong, "process name matches a known miner")
		}
		cmd := strings.Join(p.Cmdline, " ")
		if stratumRe.MatchString(cmd) {
			strong = append(strong, "command line references a stratum pool URL")
		}
		if minerArgsRe.MatchString(cmd) {
			strong = append(strong, "command line uses miner arguments")
		}
		if conns := poolConns[p.PID]; len(conns) > 0 {
			strong = append(strong, "connected to mining-pool port(s) "+strings.Join(conns, ", "))
		}
		if p.CPUPercent >= highCPU {
			exe := p.ExePath()
			if p.ExeDeleted() || hasPrefixAny(exe, stagingPrefixes) || hiddenPath(exe) {
				weak = append(weak, fmt.Sprintf("sustained %.0f%% CPU from a deleted, hidden or world-writable binary", p.CPUPercent))
			}
		}
		if len(strong) == 0 && len(weak) == 0 {
			continue
		}
		sev := audit.Critical
		label := "crypto-miner"
		if len(strong) == 0 {
			sev = audit.High
			label = "possible crypto-miner"
		}
		out = append(out, audit.Finding{
			Target:   procTarget(p),
			Severity: sev,
			Message:  fmt.Sprintf("%s (pid %d) looks like a %s: %s", p.Comm, p.PID, label, strings.Join(append(strong, weak...), "; ")),
			Evidence: procEvidence(p),
			Fix:      killFix(p),
		})
	}
	return out, nil
}

func runPoolConnections(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	socks, err := h.Sockets()
	if err != nil {
		if host.IsNotExist(err) {
			return nil, audit.Skip("procfs socket tables unavailable")
		}
		return nil, err
	}
	owners := h.SocketOwners()
	var out []audit.Finding
	for _, s := range socks {
		if !strings.HasPrefix(s.Proto, "tcp") || s.State != host.StateEstablished || !PoolPorts[s.Remote.Port()] {
			continue
		}
		who := "unknown process"
		var ev []string
		if p, ok := owners[s.Inode]; ok {
			who = fmt.Sprintf("%s (pid %d)", p.Comm, p.PID)
			ev = procEvidence(p)
		}
		out = append(out, audit.Finding{
			Target:   fmt.Sprintf("tcp/%s->%s", s.Local, s.Remote),
			Message:  fmt.Sprintf("%s has an established connection to %s, a common stratum mining-pool port", who, s.Remote),
			Evidence: ev,
			Fix:      fmt.Sprintf("# Block egress while investigating:\niptables -I OUTPUT -d %s -j DROP", s.Remote.Addr()),
		})
	}
	return out, nil
}

var binDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}

func runRecentBinaries(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	cutoff := h.Now().Add(-h.RecentWindow)
	var out []audit.Finding
	for _, d := range binDirs {
		if fi, err := h.Lstat(d); err != nil || !fi.IsDir() {
			continue // usrmerge symlinks are covered by their targets
		}
		entries, err := os.ReadDir(h.Path(d))
		if err != nil {
			continue
		}
		var recent []string
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			info, err := e.Info()
			if err != nil || info.ModTime().Before(cutoff) {
				continue
			}
			recent = append(recent, fmt.Sprintf("%s (modified %s)", path.Join(d, e.Name()), info.ModTime().UTC().Format("2006-01-02 15:04")))
		}
		if len(recent) == 0 {
			continue
		}
		total := len(recent)
		if len(recent) > 15 {
			recent = append(recent[:15], fmt.Sprintf("... and %d more", total-15))
		}
		out = append(out, audit.Finding{
			Target:   d,
			Message:  fmt.Sprintf("%d %s in %s modified within the last %s", total, plural(total, "binary", "binaries"), d, h.RecentWindow),
			Evidence: recent,
			Fix:      fmt.Sprintf("# Correlate with package activity before trusting these files:\ngrep -h ' upgrade \\| install ' /var/log/dpkg.log | tail; dpkg --verify 2>/dev/null || rpm -Va 2>/dev/null\nls -la --time-style=full-iso %s | sort -k6,7 | tail", d),
		})
	}
	return out, nil
}

func runRecentKeys(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	cutoff := h.Now().Add(-h.RecentWindow)
	var out []audit.Finding
	for _, home := range h.HomeDirs() {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := path.Join(home, ".ssh", name)
			fi, err := h.Lstat(p)
			if err != nil || fi.ModTime().Before(cutoff) {
				continue
			}
			var ev []string
			if lines, err := h.Lines(p); err == nil {
				for _, l := range lines {
					if pk, comment, _, _, err := xssh.ParseAuthorizedKey([]byte(l.Text)); err == nil {
						ev = append(ev, fmt.Sprintf("line %d: %s %s %s", l.N, pk.Type(), xssh.FingerprintSHA256(pk), comment))
					}
				}
			}
			out = append(out, audit.Finding{
				Target:   p,
				Message:  fmt.Sprintf("%s was modified %s ago", p, h.Now().Sub(fi.ModTime()).Round(1e9)),
				Evidence: ev,
				Fix:      fmt.Sprintf("# Confirm every key below is expected; remove unknown ones:\nssh-keygen -lf %s", audit.ShellQuote(p)),
			})
		}
	}
	return out, nil
}

// runPackageIntegrity compares system binaries against dpkg's md5sums
// manifests, catching trojaned ps/ls/netstat/sshd replacements.
func runPackageIntegrity(ctx context.Context, h *host.Host) ([]audit.Finding, error) {
	manifests := h.Glob("/var/lib/dpkg/info/*.md5sums")
	if len(manifests) == 0 {
		return nil, audit.Skip("no dpkg md5sums manifests (non-Debian host)")
	}
	diverted := dpkgDiversions(h)
	var out []audit.Finding
	for _, m := range manifests {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		lines, err := h.Lines(m)
		if err != nil {
			continue
		}
		pkg := strings.TrimSuffix(path.Base(m), ".md5sums")
		for _, l := range lines {
			sum, rel, ok := strings.Cut(l.Text, "  ")
			if !ok {
				continue
			}
			p := "/" + strings.TrimPrefix(rel, "/")
			if !inBinDir(p) || diverted[p] {
				continue
			}
			got, err := md5File(h.Path(p))
			if err != nil || strings.EqualFold(got, sum) {
				continue
			}
			out = append(out, audit.Finding{
				Target:   p,
				Message:  fmt.Sprintf("%s does not match the checksum recorded by package %s", p, pkg),
				Evidence: []string{"expected md5 " + sum, "actual md5 " + got},
				Fix:      fmt.Sprintf("# Compare against a clean copy, then reinstall:\napt-get install --reinstall %s", strings.SplitN(pkg, ":", 2)[0]),
			})
		}
	}
	return out, nil
}

func inBinDir(p string) bool {
	d := path.Dir(p)
	return slices.Contains(binDirs, d)
}

func dpkgDiversions(h *host.Host) map[string]bool {
	out := map[string]bool{}
	lines, err := h.Lines("/var/lib/dpkg/diversions")
	if err != nil {
		return out
	}
	// The file is triples: original path, diverted-to path, package.
	for i := 0; i+1 < len(lines); i += 3 {
		out[strings.TrimSpace(lines[i].Text)] = true
		out[strings.TrimSpace(lines[i+1].Text)] = true
	}
	return out
}

func md5File(p string) (string, error) {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 128<<20 {
		return "", fmt.Errorf("skip %s", p)
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := md5.New() //nolint:gosec // see import comment
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
