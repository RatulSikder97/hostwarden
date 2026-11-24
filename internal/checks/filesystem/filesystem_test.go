package filesystem

import (
	"slices"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

const privKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n"

func TestFilesystem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		check string
		tree  testutil.Tree
		want  map[string]audit.Severity
	}{
		{"sticky tmp is fine", "HW-FS-001", testutil.Tree{"tmp": {Dir: true, Mode: 0o1777}}, nil},
		{"world-writable without sticky", "HW-FS-001", testutil.Tree{
			"tmp":           {Dir: true, Mode: 0o1777},
			"srv/uploads":   {Dir: true, Mode: 0o777},
			"proc/1/ignore": {Dir: true, Mode: 0o777},
		}, map[string]audit.Severity{"/srv/uploads": audit.SeverityUnset}},
		{"distro setuid", "HW-FS-002", testutil.Tree{"usr/bin/passwd": {Mode: 0o4755}, "usr/bin/sudo": {Mode: 0o4755}}, nil},
		{"unexpected setuid", "HW-FS-002", testutil.Tree{
			"usr/bin/find":    {Mode: 0o4755},
			"opt/app/helper":  {Mode: 0o2755},
			"dev/shm/.x/bash": {Mode: 0o4755},
			"home/u/passwd":   {Mode: 0o4755},
			"usr/bin/regular": {Mode: 0o755},
		}, map[string]audit.Severity{
			"/usr/bin/find": audit.High, "/opt/app/helper": audit.High,
			"/dev/shm/.x/bash": audit.Critical, "/home/u/passwd": audit.Critical,
		}},
		{"shadow ok", "HW-FS-004", testutil.Tree{"etc/shadow": {Mode: 0o640}, "etc/passwd": {Mode: 0o644}}, nil},
		{"shadow world readable", "HW-FS-004", testutil.Tree{"etc/shadow": {Mode: 0o644}, "etc/passwd": {Mode: 0o666}}, map[string]audit.Severity{
			"/etc/shadow": audit.Critical, "/etc/passwd": audit.Critical,
		}},
		{"sudoers group writable", "HW-FS-004", testutil.Tree{"etc/sudoers": {Mode: 0o460}}, map[string]audit.Severity{"/etc/sudoers": audit.High}},
		{"keys locked down", "HW-FS-005", testutil.Tree{
			"etc/ssh/ssh_host_rsa_key":     {Content: privKey, Mode: 0o600},
			"etc/ssh/ssh_host_rsa_key.pub": {Content: "ssh-rsa AAAA", Mode: 0o644},
		}, nil},
		{"readable keys", "HW-FS-005", testutil.Tree{
			"root/.ssh/id_ed25519":     {Content: privKey, Mode: 0o644},
			"etc/ssl/private/site.key": {Content: "-----BEGIN PRIVATE KEY-----\nx\n", Mode: 0o640},
			"srv/app/cert.pem":         {Content: "-----BEGIN CERTIFICATE-----\nx\n", Mode: 0o644},
		}, map[string]audit.Severity{"/root/.ssh/id_ed25519": audit.Critical, "/etc/ssl/private/site.key": audit.High}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := testutil.RunCheck(t, Checks(), tc.check, testutil.Host(testutil.Build(t, tc.tree)))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("targets = %v, want %v", testutil.Targets(got), tc.want)
			}
			for _, f := range got {
				want, ok := tc.want[f.Target]
				if !ok {
					t.Errorf("unexpected finding %s", f.Target)
					continue
				}
				if want != audit.SeverityUnset && f.Severity != want {
					t.Errorf("%s severity = %v, want %v", f.Target, f.Severity, want)
				}
			}
		})
	}
}

func TestTmpMounts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mounts string
		want   []string
	}{
		{"hardened", "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n", nil},
		{"no tmp mount", "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n", []string{"/tmp"}},
		{"exec allowed", "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\ntmpfs /dev/shm tmpfs rw 0 0\n", []string{"/tmp", "/dev/shm"}},
		{"last mount wins", "tmpfs /tmp tmpfs rw 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := testutil.Build(t, testutil.Tree{"proc/mounts": {Content: tc.mounts}, "tmp": {Dir: true, Mode: 0o1777}})
			got, err := testutil.RunCheck(t, Checks(), "HW-FS-003", testutil.Host(root))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(testutil.Targets(got), tc.want) {
				t.Errorf("targets = %v, want %v", testutil.Targets(got), tc.want)
			}
		})
	}
}
