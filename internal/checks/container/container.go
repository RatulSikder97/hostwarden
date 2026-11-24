// Package container audits the Docker daemon, its socket and running containers.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

// Checks returns the container checks.
func Checks() []audit.Check {
	return []audit.Check{
		{
			ID:          "HW-CTR-001",
			Title:       "Docker socket accessible to all local users",
			Category:    audit.CategoryContainer,
			Severity:    audit.Critical,
			Rationale:   "Access to docker.sock is root on the host: `docker run -v /:/host --privileged` escapes trivially.",
			Remediation: "Restore the socket to `root:docker` mode 0660 and audit docker group membership.",
			Fix:         "chown root:docker /run/docker.sock && chmod 660 /run/docker.sock",
			Run:         runSocketPerms,
		},
		{
			ID:       "HW-CTR-002",
			Title:    "Docker daemon listening on TCP without TLS",
			Category: audit.CategoryContainer,
			Severity: audit.Critical,
			Rationale: "An unauthenticated Docker API on tcp://0.0.0.0:2375 is mass-scanned and exploited within minutes to deploy " +
				"crypto-miners (TeamTNT, Kinsing).",
			Remediation: "Remove tcp:// hosts from daemon.json/systemd overrides, or require mutual TLS (`tlsverify: true`).",
			Run:         runDaemonTCP,
		},
		{
			ID:          "HW-CTR-003",
			Title:       "Users in the docker group (root-equivalent)",
			Category:    audit.CategoryContainer,
			Severity:    audit.Medium,
			Rationale:   "Membership in the docker group grants root on the host. It is frequently handed out for convenience and forgotten.",
			Remediation: "Remove users who do not need Docker (`gpasswd -d <user> docker`); consider rootless Docker.",
			Run:         runDockerGroup,
		},
		{
			ID:          "HW-CTR-004",
			Title:       "Privileged container or dangerous capabilities",
			Category:    audit.CategoryContainer,
			Severity:    audit.High,
			Rationale:   "--privileged and CAP_SYS_ADMIN disable most container isolation; an RCE inside the container becomes host root.",
			Remediation: "Drop --privileged; grant only the specific capabilities and devices required.",
			Run:         apiCheck(privileged),
		},
		{
			ID:          "HW-CTR-005",
			Title:       "Docker socket or sensitive host path mounted into container",
			Category:    audit.CategoryContainer,
			Severity:    audit.Critical,
			Rationale:   "Mounting docker.sock, / or /etc into a container hands host control to whatever runs inside it.",
			Remediation: "Remove the mount; use a socket proxy with an allow-list if API access is unavoidable.",
			Run:         apiCheck(sensitiveMounts),
		},
		{
			ID:          "HW-CTR-006",
			Title:       "Container runs as root",
			Category:    audit.CategoryContainer,
			Severity:    audit.Low,
			Rationale:   "Root inside the container shares UID 0 with the host kernel; combined with any breakout it is host root.",
			Remediation: "Set USER in the image or `--user` at runtime, or enable user namespace remapping.",
			Run:         apiCheck(runsAsRoot),
		},
		{
			ID:          "HW-CTR-007",
			Title:       "Container shares host namespaces",
			Category:    audit.CategoryContainer,
			Severity:    audit.Medium,
			Rationale:   "--network=host exposes every container port on the host interfaces and bypasses Docker's firewall rules; --pid=host exposes host processes.",
			Remediation: "Use bridge networking with explicit -p mappings bound to 127.0.0.1 where possible; avoid --pid=host.",
			Run:         apiCheck(hostNamespaces),
		},
	}
}

func dockerSocketPath(h *host.Host) (string, fs.FileInfo, bool) {
	paths := []string{"/run/docker.sock"}
	// /var/run is normally an absolute symlink to /run; following it would
	// escape a non-live root, so only check it when it is a real directory.
	if fi, err := h.Lstat("/var/run"); err == nil && fi.IsDir() {
		paths = append(paths, "/var/run/docker.sock")
	}
	for _, p := range paths {
		if fi, err := h.Lstat(p); err == nil {
			return p, fi, true
		}
	}
	return "", nil, false
}

func runSocketPerms(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	p, fi, ok := dockerSocketPath(h)
	if !ok {
		return nil, audit.Skip("no docker socket")
	}
	perm := fi.Mode().Perm()
	if perm&0o006 == 0 {
		return nil, nil
	}
	return []audit.Finding{{
		Target:  p,
		Message: fmt.Sprintf("%s has mode %04o: any local user can control Docker", p, perm),
		Fix:     fmt.Sprintf("chmod 660 %s", p),
	}}, nil
}

var tcpHost = regexp.MustCompile(`(?:-H|--host)[= ]\s*tcp://\S+|"tcp://[^"]+"`)

func runDaemonTCP(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	var out []audit.Finding
	if b, err := h.ReadFile("/etc/docker/daemon.json"); err == nil {
		var cfg struct {
			Hosts     []string `json:"hosts"`
			TLSVerify bool     `json:"tlsverify"`
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, fmt.Errorf("parse /etc/docker/daemon.json: %w", err)
		}
		for _, hst := range cfg.Hosts {
			if strings.HasPrefix(hst, "tcp://") && !cfg.TLSVerify {
				out = append(out, tcpFinding("/etc/docker/daemon.json", hst))
			}
		}
	}
	units := h.Glob("/etc/systemd/system/docker.service.d/*.conf")
	units = append(units, h.Glob("/etc/systemd/system/docker.service")...)
	for _, u := range units {
		lines, err := h.Lines(u)
		if err != nil {
			continue
		}
		for _, l := range lines {
			if !strings.HasPrefix(strings.TrimSpace(l.Text), "ExecStart=") || strings.Contains(l.Text, "--tlsverify") {
				continue
			}
			for _, m := range tcpHost.FindAllString(l.Text, -1) {
				_, addr, _ := strings.Cut(m, "tcp://")
				out = append(out, tcpFinding(fmt.Sprintf("%s:%d", u, l.N), "tcp://"+strings.Trim(addr, `"`)))
			}
		}
	}
	return out, nil
}

func tcpFinding(source, addr string) audit.Finding {
	sev := audit.Critical
	if strings.Contains(addr, "127.0.0.1") || strings.Contains(addr, "localhost") {
		sev = audit.High // still reachable by any local user / SSRF
	}
	return audit.Finding{
		Target:   source,
		Severity: sev,
		Message:  fmt.Sprintf("Docker API served on %s without TLS client verification", addr),
		Evidence: []string{source + ": " + addr},
	}
}

func runDockerGroup(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	groups, err := h.Groups()
	if err != nil {
		return nil, audit.Skip("no /etc/group")
	}
	for _, g := range groups {
		if g.Name != "docker" || len(g.Members) == 0 {
			continue
		}
		out := make([]audit.Finding, 0, len(g.Members))
		for _, m := range g.Members {
			out = append(out, audit.Finding{
				Target:  "user:" + m,
				Message: fmt.Sprintf("user %q is in the docker group and is effectively root", m),
				Fix:     fmt.Sprintf("gpasswd -d %s docker", m),
			})
		}
		return out, nil
	}
	return nil, nil
}

// apiCheck adapts a per-container evaluator into a Run func that skips when
// the Docker API is unavailable.
func apiCheck(eval func(host.Container) []audit.Finding) func(context.Context, *host.Host) ([]audit.Finding, error) {
	return func(ctx context.Context, h *host.Host) ([]audit.Finding, error) {
		if h.Docker == nil {
			return nil, audit.Skip("Docker API not available")
		}
		cts, err := h.Docker.Containers(ctx)
		if err != nil {
			return nil, audit.Skip("Docker API not reachable: %v", err)
		}
		var out []audit.Finding
		for _, c := range cts {
			out = append(out, eval(c)...)
		}
		return out, nil
	}
}

func containerTarget(c host.Container) string { return "container:" + c.Name }

var dangerousCaps = []string{"ALL", "SYS_ADMIN", "CAP_SYS_ADMIN", "SYS_PTRACE", "CAP_SYS_PTRACE", "SYS_MODULE", "CAP_SYS_MODULE", "DAC_READ_SEARCH", "CAP_DAC_READ_SEARCH"}

func privileged(c host.Container) []audit.Finding {
	if c.Privileged {
		return []audit.Finding{{
			Target:   containerTarget(c),
			Message:  fmt.Sprintf("container %s (%s) runs --privileged", c.Name, c.Image),
			Evidence: []string{"HostConfig.Privileged=true"},
		}}
	}
	var caps []string
	for _, cp := range c.CapAdd {
		if slices.Contains(dangerousCaps, strings.ToUpper(cp)) {
			caps = append(caps, cp)
		}
	}
	if len(caps) == 0 {
		return nil
	}
	return []audit.Finding{{
		Target:   containerTarget(c),
		Message:  fmt.Sprintf("container %s (%s) adds capabilities %s", c.Name, c.Image, strings.Join(caps, ",")),
		Evidence: []string{"HostConfig.CapAdd=" + strings.Join(c.CapAdd, ",")},
	}}
}

var sensitiveHostPaths = []string{"/", "/etc", "/root", "/var/lib/docker", "/proc", "/sys", "/boot", "/home"}

func sensitiveMounts(c host.Container) []audit.Finding {
	var out []audit.Finding
	for _, m := range c.Mounts {
		var msg string
		sev := audit.SeverityUnset
		switch {
		case strings.HasSuffix(m.Source, "docker.sock") || strings.HasSuffix(m.Source, "containerd.sock"):
			msg = fmt.Sprintf("container %s mounts the container runtime socket %s", c.Name, m.Source)
		case slices.Contains(sensitiveHostPaths, strings.TrimRight(m.Source, "/")) || m.Source == "/":
			msg = fmt.Sprintf("container %s mounts host path %s at %s", c.Name, m.Source, m.Destination)
			if !m.ReadWrite {
				sev = audit.High
				msg += " (read-only)"
			}
		default:
			continue
		}
		out = append(out, audit.Finding{
			Target:   containerTarget(c) + ":" + m.Destination,
			Severity: sev,
			Message:  msg,
			Evidence: []string{fmt.Sprintf("%s -> %s rw=%t", m.Source, m.Destination, m.ReadWrite)},
		})
	}
	return out
}

func runsAsRoot(c host.Container) []audit.Finding {
	u := strings.SplitN(c.User, ":", 2)[0]
	if u != "" && u != "0" && u != "root" {
		return nil
	}
	return []audit.Finding{{
		Target:  containerTarget(c),
		Message: fmt.Sprintf("container %s (%s) runs as root", c.Name, c.Image),
	}}
}

func hostNamespaces(c host.Container) []audit.Finding {
	var ns []string
	if c.NetworkMode == "host" {
		ns = append(ns, "network")
	}
	if c.PidMode == "host" {
		ns = append(ns, "pid")
	}
	if len(ns) == 0 {
		return nil
	}
	return []audit.Finding{{
		Target:  containerTarget(c),
		Message: fmt.Sprintf("container %s (%s) shares the host %s namespace", c.Name, c.Image, strings.Join(ns, " and ")),
	}}
}
