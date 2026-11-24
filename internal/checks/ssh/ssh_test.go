package ssh

import (
	"context"
	"slices"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

func run(t *testing.T, id string, tree testutil.Tree) ([]audit.Finding, error) {
	t.Helper()
	idx := slices.IndexFunc(Checks(), func(c audit.Check) bool { return c.ID == id })
	if idx < 0 {
		t.Fatalf("no check %s", id)
	}
	return Checks()[idx].Run(context.Background(), testutil.Host(testutil.Build(t, tree)))
}

func targets(fs []audit.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Target)
	}
	return out
}

func TestSSHDSettings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		check  string
		config string
		extra  testutil.Tree
		want   []string
	}{
		{"password default is yes", "HW-SSH-001", "Port 22\n", nil, []string{"/etc/ssh/sshd_config"}},
		{"password disabled", "HW-SSH-001", "PasswordAuthentication no\n", nil, nil},
		{"first value wins", "HW-SSH-001", "PasswordAuthentication no\nPasswordAuthentication yes\n", nil, nil},
		{"equals syntax and case", "HW-SSH-001", "passwordauthentication=YES\n", nil, []string{"/etc/ssh/sshd_config"}},
		{
			"include wins when first", "HW-SSH-001",
			"Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n",
			testutil.Tree{"etc/ssh/sshd_config.d/50-cloud-init.conf": {Content: "PasswordAuthentication yes\n"}},
			[]string{"/etc/ssh/sshd_config.d/50-cloud-init.conf"},
		},
		{
			"relative include", "HW-SSH-001",
			"Include sshd_config.d/*.conf\n",
			testutil.Tree{"etc/ssh/sshd_config.d/a.conf": {Content: "PasswordAuthentication no\n"}},
			nil,
		},
		{"match block ignored", "HW-SSH-005", "PasswordAuthentication no\nMatch User x\n  PermitEmptyPasswords yes\n", nil, nil},
		{"empty passwords", "HW-SSH-005", "PermitEmptyPasswords yes\n", nil, []string{"/etc/ssh/sshd_config"}},
		{"root login default ok", "HW-SSH-002", "", nil, nil},
		{"root login yes", "HW-SSH-002", "PermitRootLogin yes\n", nil, []string{"/etc/ssh/sshd_config"}},
		{"maxauthtries default 6", "HW-SSH-004", "", nil, []string{"/etc/ssh/sshd_config"}},
		{"maxauthtries 3", "HW-SSH-004", "MaxAuthTries 3\n", nil, nil},
		{"modern algorithms", "HW-SSH-003", "Ciphers aes256-gcm@openssh.com\nMACs hmac-sha2-256-etm@openssh.com\n", nil, nil},
		{"removal list ignored", "HW-SSH-003", "Ciphers -aes128-cbc\n", nil, nil},
		{
			"weak kex and appended mac", "HW-SSH-003", "KexAlgorithms diffie-hellman-group14-sha1,curve25519-sha256\nMACs +hmac-md5\n", nil,
			[]string{"/etc/ssh/sshd_config#KexAlgorithms", "/etc/ssh/sshd_config#MACs"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tree := testutil.Tree{"etc/ssh/sshd_config": {Content: tc.config}}
			for k, v := range tc.extra {
				tree[k] = v
			}
			got, err := run(t, tc.check, tree)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(targets(got), tc.want) {
				t.Errorf("targets = %v, want %v", targets(got), tc.want)
			}
		})
	}
}

func TestSkipWithoutSSHD(t *testing.T) {
	t.Parallel()
	_, err := run(t, "HW-SSH-001", testutil.Tree{"etc/hostname": {Content: "x"}})
	if _, ok := audit.IsSkip(err); !ok {
		t.Fatalf("err = %v, want skip", err)
	}
}

const rsa1024Key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC688YD4xvF5M6199cMBRcUeLeX8ycygnKOXDeptoazhVEChFFS8SlqWfsnzr5VtWSOgISDw+ybhXdShXohVX61WUBjrzxoihixBQ9Sj7varZLQnw68MiV+OF+hIRdGHWAYuWJ26zV0qCV+LfF8sVVY9GKU14qcZfgFTToBBOsMIQ== backup@example"

const ed25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJadjJmTiVD1Sj6QEj9ICdTWEmT9WYp5axQxPXehTU4K ops@example"

func TestAuthorizedKeys(t *testing.T) {
	t.Parallel()
	passwd := testutil.File{Content: "root:x:0:0:root:/root:/bin/bash\n"}
	tests := []struct {
		name string
		keys testutil.File
		want []string
	}{
		{"strong key", testutil.File{Content: ed25519Key + "\n", Mode: 0o600}, nil},
		{"dsa key", testutil.File{Content: "# legacy\nssh-dss AAAAB3NzaC1kc3MAAACB legacy\n", Mode: 0o600}, []string{"/root/.ssh/authorized_keys:2"}},
		{"short rsa key", testutil.File{Content: ed25519Key + "\n" + rsa1024Key + "\n", Mode: 0o600}, []string{"/root/.ssh/authorized_keys:2"}},
		{"group writable", testutil.File{Content: ed25519Key + "\n", Mode: 0o664}, []string{"/root/.ssh/authorized_keys"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := run(t, "HW-SSH-006", testutil.Tree{"etc/passwd": passwd, "root/.ssh/authorized_keys": tc.keys})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(targets(got), tc.want) {
				t.Errorf("targets = %v, want %v", targets(got), tc.want)
			}
		})
	}
}
