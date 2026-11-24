package host_test

import (
	"slices"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

func TestHostBasics(t *testing.T) {
	t.Parallel()
	root := testutil.Build(t, testutil.Tree{
		"etc/os-release":           {Content: "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID=ubuntu\nID_LIKE=debian\n"},
		"etc/hostname":             {Content: "fallback\n"},
		"proc/sys/kernel/hostname": {Content: "web-7\n"},
		"etc/passwd":               {Content: "root:x:0:0:root:/root:/bin/bash\nbad line\nsvc:x:998:998::/nonexistent:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/zsh\n"},
		"etc/group":                {Content: "docker:x:999:alice, bob\n"},
	})
	h := testutil.Host(root)
	if got := h.Hostname(); got != "web-7" {
		t.Errorf("Hostname = %q", got)
	}
	if got := h.OSFamily(); got != "debian" {
		t.Errorf("OSFamily = %q", got)
	}
	users, err := h.Users()
	if err != nil || len(users) != 3 {
		t.Fatalf("Users = %v, %v", users, err)
	}
	if got := h.HomeDirs(); !slices.Equal(got, []string{"/root", "/home/alice"}) {
		t.Errorf("HomeDirs = %v", got)
	}
	groups, _ := h.Groups()
	if !slices.Equal(groups[0].Members, []string{"alice", "bob"}) {
		t.Errorf("members = %v", groups[0].Members)
	}
	if h.Live() {
		t.Error("fixture host must not be live")
	}
	if got := h.Rel(h.Path("/etc/passwd")); got != "/etc/passwd" {
		t.Errorf("Rel = %q", got)
	}
}

func TestFilesPrunesProcAndSkipsSymlinks(t *testing.T) {
	t.Parallel()
	root := testutil.Build(t, testutil.Tree{
		"proc/1/root/tmp":   {Dir: true, Mode: 0o777},
		"srv/drop":          {Dir: true, Mode: 0o777},
		"dev/null":          {Content: ""},
		"dev/shm/x":         {Dir: true, Mode: 0o777},
		"usr/bin/link-suid": {Link: "/usr/bin/sudo"},
	})
	scan, err := testutil.Host(root).Files()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range scan.WorldWritableDirs {
		got = append(got, e.Path)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"/dev/shm/x", "/srv/drop"}) {
		t.Errorf("world-writable = %v", got)
	}
}
