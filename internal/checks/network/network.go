// Package network audits listening sockets and host firewall presence.
package network

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

// sensitivePort describes a service that must never face the internet.
type sensitivePort struct {
	Service  string
	Severity audit.Severity
}

// SensitivePorts maps well-known ports to services that are routinely
// compromised when bound to a public interface (unauthenticated by default,
// or a direct path to code execution).
var SensitivePorts = map[uint16]sensitivePort{
	2375:  {"Docker API (plaintext)", audit.Critical},
	2376:  {"Docker API (TLS)", audit.High},
	2379:  {"etcd", audit.Critical},
	6443:  {"Kubernetes API", audit.High},
	10250: {"kubelet API", audit.Critical},
	10255: {"kubelet read-only API", audit.High},
	6379:  {"Redis", audit.Critical},
	11211: {"Memcached", audit.High},
	27017: {"MongoDB", audit.High},
	9200:  {"Elasticsearch", audit.High},
	5432:  {"PostgreSQL", audit.High},
	3306:  {"MySQL/MariaDB", audit.High},
	5984:  {"CouchDB", audit.High},
	8500:  {"Consul HTTP API", audit.High},
	5672:  {"RabbitMQ AMQP", audit.Medium},
	15672: {"RabbitMQ management", audit.Medium},
	9000:  {"PHP-FPM / MinIO", audit.Medium},
	8888:  {"Jupyter", audit.High},
}

// Checks returns the network exposure checks.
func Checks() []audit.Check {
	return []audit.Check{
		{
			ID:       "HW-NET-001",
			Title:    "Sensitive service listening on a non-loopback address",
			Category: audit.CategoryNetwork,
			Severity: audit.High,
			Rationale: "Databases, caches, the Docker API and Kubernetes control-plane ports are the most common initial-access " +
				"vector for cryptojacking campaigns (e.g. unauthenticated Redis or Docker API on 0.0.0.0).",
			Remediation: "Bind the service to 127.0.0.1 or a private interface, enable authentication, and restrict the port with a host firewall.",
			Run:         runExposedServices,
		},
		{
			ID:          "HW-NET-002",
			Title:       "No host firewall configured",
			Category:    audit.CategoryNetwork,
			Severity:    audit.Medium,
			Rationale:   "Without a host firewall every listening socket is reachable; a single misbound service becomes internet-facing.",
			Remediation: "Enable a default-deny inbound policy with nftables, ufw or firewalld, allowing only required ports.",
			Fix: `# Debian/Ubuntu example (keeps SSH reachable):
ufw default deny incoming
ufw allow 22/tcp
ufw enable`,
			Run: runFirewall,
		},
	}
}

func runExposedServices(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	socks, err := h.Sockets()
	if err != nil {
		if host.IsNotExist(err) {
			return nil, audit.Skip("procfs socket tables unavailable")
		}
		return nil, err
	}
	owners := h.SocketOwners()
	seen := map[string]bool{}
	var out []audit.Finding
	for _, s := range socks {
		if !s.Listening() || s.Local.Addr().IsLoopback() {
			continue
		}
		svc, ok := SensitivePorts[s.Local.Port()]
		if !ok {
			continue
		}
		proto := strings.TrimSuffix(s.Proto, "6")
		target := fmt.Sprintf("%s/%s", proto, s.Local)
		if seen[target] {
			continue
		}
		seen[target] = true
		bind := s.Local.Addr().String()
		if s.Local.Addr().IsUnspecified() {
			bind += " (all interfaces)"
		}
		evidence := []string{fmt.Sprintf("%s listen %s", s.Proto, s.Local)}
		proc := "unknown process"
		if p, ok := owners[s.Inode]; ok {
			proc = fmt.Sprintf("%s (pid %d)", p.Comm, p.PID)
			evidence = append(evidence, fmt.Sprintf("process %s: %s", proc, p.CommandLine()))
		}
		out = append(out, audit.Finding{
			Target:   target,
			Severity: svc.Severity,
			Message:  fmt.Sprintf("%s port %d bound to %s by %s", svc.Service, s.Local.Port(), bind, proc),
			Evidence: evidence,
			Fix: fmt.Sprintf("# Rebind %s to 127.0.0.1 in its config, or block it:\nnft add rule inet filter input tcp dport %d drop 2>/dev/null || iptables -I INPUT -p tcp --dport %d -j DROP",
				svc.Service, s.Local.Port(), s.Local.Port()),
		})
	}
	return out, nil
}

var (
	iptablesRule = regexp.MustCompile(`(?m)^-A\s+\S+`)
	nftRule      = regexp.MustCompile(`(?m)\bpolicy\s+drop\b|\b(drop|reject)\b`)
	ufwEnabled   = regexp.MustCompile(`(?m)^\s*ENABLED\s*=\s*yes\s*$`)
)

// firewallEvidence returns how a firewall was detected, or "" if none was.
// Detection is configuration-based: hostwarden does not open netlink sockets.
func firewallEvidence(h *host.Host) string {
	if b, err := h.ReadFile("/etc/ufw/ufw.conf"); err == nil && ufwEnabled.Match(b) {
		return "ufw enabled (/etc/ufw/ufw.conf)"
	}
	for _, unit := range []string{"firewalld.service", "nftables.service", "netfilter-persistent.service", "iptables.service"} {
		for _, wants := range []string{"multi-user.target.wants", "sysinit.target.wants", "basic.target.wants"} {
			p := "/etc/systemd/system/" + wants + "/" + unit
			if h.Exists(p) {
				if unit == "nftables.service" {
					if b, err := h.ReadFile("/etc/nftables.conf"); err != nil || !nftRule.Match(b) {
						continue
					}
				}
				return unit + " enabled (" + p + ")"
			}
		}
	}
	for _, p := range []string{"/etc/iptables/rules.v4", "/etc/sysconfig/iptables"} {
		if b, err := h.ReadFile(p); err == nil && iptablesRule.Match(b) {
			return "persisted iptables rules (" + p + ")"
		}
	}
	return ""
}

func runFirewall(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	if ev := firewallEvidence(h); ev != "" {
		return nil, nil
	}
	return []audit.Finding{{
		Target:  "host-firewall",
		Message: "no enabled nftables, iptables, ufw or firewalld configuration found",
		Evidence: []string{
			"checked /etc/ufw/ufw.conf, /etc/nftables.conf, /etc/iptables/rules.v4, /etc/sysconfig/iptables and enabled systemd units",
		},
	}}, nil
}
