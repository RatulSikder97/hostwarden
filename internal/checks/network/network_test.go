package network

import (
	"slices"
	"strings"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

const hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func row(local, remote, state, inode string) string {
	return "   0: " + local + " " + remote + " " + state + " 00000000:00000000 00:00000000 00000000   100        0 " + inode + " 1 0000000000000000 100 0 0 10 0\n"
}

func TestExposedServices(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		tcp     string
		tcp6    string
		udp     string
		want    []string
		wantSev audit.Severity
		wantMsg string
	}{
		{name: "redis on loopback", tcp: row("0100007F:18EB", "00000000:0000", "0A", "11"), want: nil},
		{name: "redis on all interfaces", tcp: row("00000000:18EB", "00000000:0000", "0A", "11"), want: []string{"tcp/0.0.0.0:6379"}, wantSev: audit.Critical, wantMsg: "redis-server (pid 77)"},
		{name: "postgres on private ip", tcp: row("0A00000A:1538", "00000000:0000", "0A", "12"), want: []string{"tcp/10.0.0.10:5432"}, wantSev: audit.High},
		{name: "ssh is not sensitive", tcp: row("00000000:0016", "00000000:0000", "0A", "13"), want: nil},
		{name: "established is not listening", tcp: row("0500000A:18EB", "0900000A:C000", "01", "14"), want: nil},
		{name: "docker api on ipv6 any", tcp6: row("00000000000000000000000000000000:0947", "00000000000000000000000000000000:0000", "0A", "15"), want: []string{"tcp/[::]:2375"}, wantSev: audit.Critical},
		{name: "ipv4-mapped ipv6 loopback", tcp6: row("0000000000000000FFFF00000100007F:18EB", "00000000000000000000000000000000:0000", "0A", "16"), want: nil},
		{name: "memcached udp", udp: row("00000000:2BCB", "00000000:0000", "07", "17"), want: []string{"udp/0.0.0.0:11211"}, wantSev: audit.High},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := testutil.Build(t, testutil.Tree{
				"proc/net/tcp":    {Content: hdr + tc.tcp},
				"proc/net/tcp6":   {Content: hdr + tc.tcp6},
				"proc/net/udp":    {Content: hdr + tc.udp},
				"proc/77/comm":    {Content: "redis-server\n"},
				"proc/77/cmdline": {Content: "redis-server\x00*:6379\x00"},
				"proc/77/fd/6":    {Link: "socket:[11]"},
				"proc/77/fd/1":    {Link: "/dev/null"},
			})
			got, err := testutil.RunCheck(t, Checks(), "HW-NET-001", testutil.Host(root))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(testutil.Targets(got), tc.want) {
				t.Fatalf("targets = %v, want %v", testutil.Targets(got), tc.want)
			}
			if len(got) == 1 {
				if got[0].Severity != tc.wantSev {
					t.Errorf("severity = %v, want %v", got[0].Severity, tc.wantSev)
				}
				if !strings.Contains(got[0].Message, tc.wantMsg) {
					t.Errorf("message %q does not contain %q", got[0].Message, tc.wantMsg)
				}
			}
		})
	}
}

func TestFirewall(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tree testutil.Tree
		want bool // finding expected
	}{
		{"nothing", testutil.Tree{"etc/hostname": {Content: "x"}}, true},
		{"ufw disabled", testutil.Tree{"etc/ufw/ufw.conf": {Content: "ENABLED=no\n"}}, true},
		{"ufw enabled", testutil.Tree{"etc/ufw/ufw.conf": {Content: "ENABLED=yes\n"}}, false},
		{"nftables unit with empty ruleset", testutil.Tree{
			"etc/systemd/system/sysinit.target.wants/nftables.service": {Content: "[Unit]\n"},
			"etc/nftables.conf": {Content: "flush ruleset\ntable inet filter {\n chain input { type filter hook input priority 0; }\n}\n"},
		}, true},
		{"nftables with drop policy", testutil.Tree{
			"etc/systemd/system/sysinit.target.wants/nftables.service": {Content: "[Unit]\n"},
			"etc/nftables.conf": {Content: "table inet filter {\n chain input { type filter hook input priority 0; policy drop; }\n}\n"},
		}, false},
		{"iptables-persistent", testutil.Tree{"etc/iptables/rules.v4": {Content: "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"}}, false},
		{"firewalld", testutil.Tree{"etc/systemd/system/multi-user.target.wants/firewalld.service": {Content: "[Unit]\n"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := testutil.RunCheck(t, Checks(), "HW-NET-002", testutil.Host(testutil.Build(t, tc.tree)))
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) > 0) != tc.want {
				t.Errorf("findings = %v, want finding=%v", testutil.Targets(got), tc.want)
			}
		})
	}
}
