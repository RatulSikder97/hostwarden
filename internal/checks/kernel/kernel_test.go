package kernel

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

const debian = "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n"

func TestSysctl(t *testing.T) {
	t.Parallel()
	tree := testutil.Tree{
		"proc/sys/kernel/randomize_va_space": {Content: "1\n"},
		"proc/sys/kernel/kptr_restrict":      {Content: "2\n"},
		"proc/sys/fs/suid_dumpable":          {Content: "2\n"},
		"proc/sys/net/ipv4/tcp_syncookies":   {Content: "1\n"},
	}
	got, err := testutil.RunCheck(t, Checks(), "HW-KRN-001", testutil.Host(testutil.Build(t, tree)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"kernel.randomize_va_space", "fs.suid_dumpable"}
	if !slices.Equal(testutil.Targets(got), want) {
		t.Errorf("targets = %v, want %v", testutil.Targets(got), want)
	}
	if got[0].Severity != audit.Medium {
		t.Errorf("ASLR severity = %v, want medium", got[0].Severity)
	}
	if _, err := testutil.RunCheck(t, Checks(), "HW-KRN-001", testutil.Host(t.TempDir())); err == nil {
		t.Error("expected skip without procfs")
	}
}

func TestAutoUpdates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		tree    testutil.Tree
		want    int
		skipped bool
	}{
		{"debian enabled", testutil.Tree{
			"etc/os-release":                     {Content: debian},
			"etc/apt/apt.conf.d/20auto-upgrades": {Content: "APT::Periodic::Unattended-Upgrade \"1\";\n"},
			"usr/bin/unattended-upgrade":         {Content: "#!/usr/bin/python3\n"},
		}, 0, false},
		{"debian disabled later", testutil.Tree{
			"etc/os-release":                     {Content: debian},
			"etc/apt/apt.conf.d/20auto-upgrades": {Content: "APT::Periodic::Unattended-Upgrade \"1\";\n"},
			"etc/apt/apt.conf.d/99local":         {Content: "APT::Periodic::Unattended-Upgrade \"0\";\n"},
			"usr/bin/unattended-upgrade":         {Content: "#!/usr/bin/python3\n"},
		}, 1, false},
		{"rhel enabled", testutil.Tree{
			"etc/os-release":         {Content: "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n"},
			"etc/dnf/automatic.conf": {Content: "[commands]\napply_updates = yes\n"},
			"etc/systemd/system/timers.target.wants/dnf-automatic.timer": {Content: "[Timer]\n"},
		}, 0, false},
		{"rhel not applying", testutil.Tree{
			"etc/os-release":         {Content: "ID=almalinux\n"},
			"etc/dnf/automatic.conf": {Content: "[commands]\napply_updates = no\n"},
		}, 1, false},
		{"alpine", testutil.Tree{"etc/os-release": {Content: "ID=alpine\n"}}, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := testutil.RunCheck(t, Checks(), "HW-KRN-002", testutil.Host(testutil.Build(t, tc.tree)))
			if _, isSkip := audit.IsSkip(err); isSkip != tc.skipped {
				t.Fatalf("err = %v, skipped want %v", err, tc.skipped)
			}
			if len(got) != tc.want {
				t.Errorf("findings = %d, want %d", len(got), tc.want)
			}
		})
	}
}

type fakeExec struct {
	out []byte
	err error
	got []string
}

func (f *fakeExec) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	f.got = append([]string{name}, args...)
	return f.out, f.err
}

func TestPendingUpdates(t *testing.T) {
	t.Parallel()
	aptOut := []byte(`Reading package lists...
Inst openssl [3.0.11-1~deb12u1] (3.0.13-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst libssl3 [3.0.11-1~deb12u1] (3.0.13-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst tzdata [2024a-0+deb12u1] (2024b-0+deb12u1 Debian:12.7/stable [all])
Conf openssl (3.0.13-1~deb12u1 Debian-Security:12/stable-security [amd64])
`)
	tests := []struct {
		name    string
		tree    testutil.Tree
		exec    *fakeExec
		live    bool
		want    string
		skipped bool
	}{
		{"notifier cache", testutil.Tree{"var/lib/update-notifier/updates-available": {Content: "5 updates can be applied immediately.\n2 of these updates are standard security updates.\n"}}, nil, false, "2 security update(s) pending", false},
		{"notifier zero", testutil.Tree{"var/lib/update-notifier/updates-available": {Content: "0 updates can be applied immediately.\n0 of these updates are security updates.\n"}}, nil, false, "", false},
		{"no executor skips", testutil.Tree{"etc/os-release": {Content: debian}}, nil, false, "", true},
		{"apt simulation", testutil.Tree{"etc/os-release": {Content: debian}}, &fakeExec{out: aptOut}, true, "2 security update(s) pending", false},
		{"apt failure skips", testutil.Tree{"etc/os-release": {Content: debian}}, &fakeExec{err: errors.New("boom")}, true, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := testutil.Build(t, tc.tree)
			cfg := host.Config{Root: root}
			if tc.exec != nil {
				cfg.Exec = tc.exec
			}
			h := host.New(cfg)
			got, err := testutil.RunCheck(t, Checks(), "HW-KRN-003", h)
			if _, isSkip := audit.IsSkip(err); isSkip != tc.skipped {
				t.Fatalf("err = %v, skipped want %v", err, tc.skipped)
			}
			msg := ""
			if len(got) > 0 {
				msg = got[0].Message
			}
			if msg != tc.want {
				t.Errorf("message = %q, want %q", msg, tc.want)
			}
			if tc.live && tc.exec != nil && tc.exec.err == nil && !slices.Equal(tc.exec.got[:3], []string{"apt-get", "-s", "-o"}) {
				t.Errorf("unexpected probe command %v", tc.exec.got)
			}
		})
	}
}
