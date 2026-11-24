package accounts

import (
	"slices"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

func TestAccounts(t *testing.T) {
	t.Parallel()
	const basePasswd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
	tests := []struct {
		name  string
		check string
		tree  testutil.Tree
		want  []string
	}{
		{"single root", "HW-ACC-001", testutil.Tree{"etc/passwd": {Content: basePasswd}}, nil},
		{"toor backdoor", "HW-ACC-001", testutil.Tree{"etc/passwd": {Content: basePasswd + "toor:x:0:0::/root:/bin/sh\n"}}, []string{"user:toor"}},
		{"locked accounts", "HW-ACC-002", testutil.Tree{
			"etc/passwd": {Content: basePasswd},
			"etc/shadow": {Content: "root:!:1::::::\ndaemon:*:1::::::\n"},
		}, nil},
		{"empty shadow hash", "HW-ACC-002", testutil.Tree{
			"etc/passwd": {Content: basePasswd + "dev:x:1000:1000::/home/dev:/bin/bash\n"},
			"etc/shadow": {Content: "root:!:1::::::\ndev::1::::::\n"},
		}, []string{"user:dev"}},
		{"empty passwd field", "HW-ACC-002", testutil.Tree{"etc/passwd": {Content: "root::0:0:root:/root:/bin/bash\n"}}, []string{"user:root"}},
		{"sudo with password", "HW-ACC-003", testutil.Tree{"etc/sudoers": {Content: "%sudo ALL=(ALL:ALL) ALL\n"}}, nil},
		{"nopasswd via includedir", "HW-ACC-003", testutil.Tree{
			"etc/sudoers":          {Content: "@includedir /etc/sudoers.d\n"},
			"etc/sudoers.d/ci":     {Content: "# comment NOPASSWD\nci ALL=(ALL) NOPASSWD: ALL\n"},
			"etc/sudoers.d/backup": {Content: "backup ALL=(root) NOPASSWD: /usr/bin/rsync\n"},
		}, []string{"/etc/sudoers.d/backup:1", "/etc/sudoers.d/ci:2"}},
		{"system shell", "HW-ACC-004", testutil.Tree{"etc/passwd": {Content: basePasswd + "www-data:x:33:33::/var/www:/bin/bash\nsync:x:4:65534:sync:/bin:/bin/sync\nalice:x:1000:1000::/home/alice:/bin/zsh\n"}}, []string{"user:www-data"}},
		{"custom UID_MIN", "HW-ACC-004", testutil.Tree{
			"etc/passwd":     {Content: "svc:x:600:600::/srv:/bin/bash\n"},
			"etc/login.defs": {Content: "UID_MIN 500\n"},
		}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := testutil.RunCheck(t, Checks(), tc.check, testutil.Host(testutil.Build(t, tc.tree)))
			if err != nil {
				t.Fatal(err)
			}
			gotT := testutil.Targets(got)
			slices.Sort(gotT)
			if !slices.Equal(gotT, tc.want) {
				t.Errorf("targets = %v, want %v", gotT, tc.want)
			}
		})
	}
}
