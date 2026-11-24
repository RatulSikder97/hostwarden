package checks_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/checks"
	"github.com/RatulSikder97/hostwarden/internal/report"
	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

func scanFixture(t *testing.T, name string) *audit.Report {
	t.Helper()
	root := testutil.Fixture(t, name)
	return audit.Run(context.Background(), testutil.Host(root), checks.All(), audit.Options{Version: "test"})
}

func dump(t *testing.T, r *audit.Report) {
	t.Helper()
	if os.Getenv("HOSTWARDEN_DUMP") != "" {
		_ = report.Table(os.Stdout, r, report.TableOptions{Verbose: true, Width: 140})
	}
}

func TestHardenedFixtureIsClean(t *testing.T) {
	t.Parallel()
	r := scanFixture(t, "hardened")
	dump(t, r)
	for _, f := range r.Findings {
		t.Errorf("unexpected finding %s %s: %s", f.CheckID, f.Target, f.Message)
	}
	if len(r.Errors) > 0 {
		t.Errorf("check errors: %+v", r.Errors)
	}
	if r.Score != 100 || r.Grade != "A" {
		t.Errorf("score = %d (%s), want 100 (A)", r.Score, r.Grade)
	}
}

func TestCompromisedFixture(t *testing.T) {
	t.Parallel()
	r := scanFixture(t, "compromised")
	dump(t, r)
	if len(r.Errors) > 0 {
		t.Fatalf("check errors: %+v", r.Errors)
	}
	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.CheckID+" "+f.Target] = true
	}
	want := []string{
		"HW-SSH-001 /etc/ssh/sshd_config.d/50-cloud-init.conf",
		"HW-SSH-002 /etc/ssh/sshd_config.d/50-cloud-init.conf",
		"HW-SSH-003 /etc/ssh/sshd_config.d/50-cloud-init.conf#Ciphers",
		"HW-SSH-003 /etc/ssh/sshd_config.d/50-cloud-init.conf#MACs",
		"HW-SSH-004 /etc/ssh/sshd_config.d/50-cloud-init.conf",
		"HW-SSH-006 /root/.ssh/authorized_keys:2",
		"HW-SSH-006 /home/deploy/.ssh/authorized_keys",
		"HW-SSH-006 /home/deploy/.ssh/authorized_keys:1",
		"HW-ACC-001 user:toor",
		"HW-ACC-002 user:deploy",
		"HW-ACC-003 /etc/sudoers.d/90-deploy:2",
		"HW-ACC-003 /etc/sudoers.d/90-deploy:3",
		"HW-ACC-004 user:www-data",
		"HW-NET-001 tcp/0.0.0.0:6379",
		"HW-NET-001 tcp/[::]:2375",
		"HW-NET-002 host-firewall",
		"HW-FS-001 /var/tmp/.cache",
		"HW-FS-002 /tmp/.ICE-unix/.s",
		"HW-FS-002 /usr/bin/find",
		"HW-FS-003 /tmp",
		"HW-FS-003 /dev/shm",
		"HW-FS-004 /etc/shadow",
		"HW-FS-005 /etc/ssh/ssh_host_ed25519_key",
		"HW-FS-005 /home/deploy/.ssh/id_rsa",
		"HW-CTR-001 /run/docker.sock",
		"HW-CTR-002 /etc/docker/daemon.json",
		"HW-CTR-003 user:deploy",
		"HW-CTR-003 user:www-data",
		"HW-IOC-001 /etc/ld.so.preload:1",
		"HW-IOC-002 /etc/cron.d/sysupdate:2",
		"HW-IOC-002 /var/spool/cron/crontabs/www-data:2",
		"HW-IOC-003 /etc/systemd/system/system-update.service:5",
		"HW-IOC-004 /etc/rc.local:2",
		"HW-IOC-004 /etc/rc.local:3",
		"HW-IOC-005 pid:1500",
		"HW-IOC-005 pid:4242",
		"HW-IOC-006 pid:4242",
		"HW-IOC-006 pid:4300",
		"HW-IOC-007 pid:4242",
		"HW-IOC-007 pid:4300",
		"HW-IOC-008 tcp/10.0.0.5:51234->198.51.100.7:3333",
		"HW-IOC-009 /usr/bin",
		"HW-IOC-010 /root/.ssh/authorized_keys",
		"HW-IOC-011 /usr/bin/ls",
		"HW-KRN-001 kernel.randomize_va_space",
		"HW-KRN-001 kernel.dmesg_restrict",
		"HW-KRN-001 fs.protected_symlinks",
		"HW-KRN-002 unattended-upgrades",
		"HW-KRN-003 packages",
		"HW-KRN-004 /run/reboot-required",
	}
	var missing []string
	for _, w := range want {
		if !got[w] {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		var have []string
		for k := range got {
			have = append(have, k)
		}
		slices.Sort(have)
		t.Fatalf("missing findings:\n  %s\nhave:\n  %s", strings.Join(missing, "\n  "), strings.Join(have, "\n  "))
	}
	if len(r.Findings) != len(want) {
		var extra []string
		for k := range got {
			if !slices.Contains(want, k) {
				extra = append(extra, k)
			}
		}
		t.Errorf("got %d findings, want %d; unexpected: %v", len(r.Findings), len(want), extra)
	}

	// Spot-check severity escalation logic.
	sev := func(id, target string) audit.Severity {
		for _, f := range r.Findings {
			if f.CheckID == id && f.Target == target {
				return f.Severity
			}
		}
		return audit.SeverityUnset
	}
	for _, tc := range []struct {
		id, target string
		want       audit.Severity
	}{
		{"HW-IOC-007", "pid:4242", audit.Critical},
		{"HW-IOC-007", "pid:4300", audit.High},
		{"HW-IOC-005", "pid:1500", audit.Low},
		{"HW-FS-002", "/tmp/.ICE-unix/.s", audit.Critical},
		{"HW-FS-004", "/etc/shadow", audit.Critical},
		{"HW-ACC-003", "/etc/sudoers.d/90-deploy:2", audit.High},
		{"HW-NET-001", "tcp/0.0.0.0:6379", audit.Critical},
		{"HW-KRN-001", "kernel.randomize_va_space", audit.Medium},
	} {
		if got := sev(tc.id, tc.target); got != tc.want {
			t.Errorf("%s %s severity = %v, want %v", tc.id, tc.target, got, tc.want)
		}
	}
	if r.Score != 0 || r.Grade != "F" {
		t.Errorf("score = %d (%s), want 0 (F)", r.Score, r.Grade)
	}
	// Docker API checks skip cleanly without a client.
	if !slices.ContainsFunc(r.Skipped, func(s audit.CheckStatus) bool { return s.CheckID == "HW-CTR-004" }) {
		t.Errorf("HW-CTR-004 should be skipped without a Docker API, skipped=%v", r.Skipped)
	}
}

func TestCatalogueIsWellFormed(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, c := range checks.All() {
		if seen[c.ID] {
			t.Errorf("duplicate check ID %s", c.ID)
		}
		seen[c.ID] = true
		if c.Title == "" || c.Rationale == "" || c.Remediation == "" || c.Run == nil || c.Severity == audit.SeverityUnset || c.Category == "" {
			t.Errorf("check %s is missing metadata", c.ID)
		}
		if !strings.HasPrefix(c.ID, "HW-") {
			t.Errorf("check %s does not use the HW- prefix", c.ID)
		}
	}
}

func TestSelect(t *testing.T) {
	t.Parallel()
	all := checks.All()
	tests := []struct {
		name             string
		include, exclude []string
		wantN            int
		wantErr          bool
	}{
		{name: "all", wantN: len(all)},
		{name: "by prefix", include: []string{"HW-SSH"}, wantN: 6},
		{name: "by category", include: []string{"compromise"}, wantN: 11},
		{name: "by id", include: []string{"hw-ioc-007"}, wantN: 1},
		{name: "exclude category", exclude: []string{"container", "kernel"}, wantN: len(all) - 8},
		{name: "unknown", include: []string{"HW-NOPE"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checks.Select(all, tc.include, tc.exclude)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && len(got) != tc.wantN {
				t.Errorf("selected %d checks, want %d", len(got), tc.wantN)
			}
		})
	}
}

func ExampleSelect() {
	sel, _ := checks.Select(checks.All(), []string{"HW-SSH-001", "HW-IOC-007"}, nil)
	for _, c := range sel {
		fmt.Println(c.ID, c.Severity)
	}
	// Output:
	// HW-SSH-001 high
	// HW-IOC-007 critical
}
