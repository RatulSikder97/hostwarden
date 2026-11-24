package host

import (
	"strconv"
	"strings"
)

// User is an /etc/passwd entry.
type User struct {
	Name   string
	Passwd string
	UID    int
	GID    int
	Home   string
	Shell  string
	Line   int
}

// ShadowEntry is an /etc/shadow entry.
type ShadowEntry struct {
	Name string
	Hash string
	Line int
}

// Group is an /etc/group entry.
type Group struct {
	Name    string
	GID     int
	Members []string
}

// Users parses /etc/passwd.
func (h *Host) Users() ([]User, error) {
	lines, err := h.Lines("/etc/passwd")
	if err != nil {
		return nil, err
	}
	var out []User
	for _, l := range lines {
		f := strings.Split(l.Text, ":")
		if len(f) < 7 || strings.HasPrefix(strings.TrimSpace(f[0]), "#") {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, User{Name: f[0], Passwd: f[1], UID: uid, GID: gid, Home: f[5], Shell: f[6], Line: l.N})
	}
	return out, nil
}

// Shadow parses /etc/shadow.
func (h *Host) Shadow() ([]ShadowEntry, error) {
	lines, err := h.Lines("/etc/shadow")
	if err != nil {
		return nil, err
	}
	var out []ShadowEntry
	for _, l := range lines {
		f := strings.Split(l.Text, ":")
		if len(f) < 2 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		out = append(out, ShadowEntry{Name: f[0], Hash: f[1], Line: l.N})
	}
	return out, nil
}

// Groups parses /etc/group.
func (h *Host) Groups() ([]Group, error) {
	lines, err := h.Lines("/etc/group")
	if err != nil {
		return nil, err
	}
	var out []Group
	for _, l := range lines {
		f := strings.Split(l.Text, ":")
		if len(f) < 4 || strings.HasPrefix(f[0], "#") {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		var members []string
		for m := range strings.SplitSeq(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		out = append(out, Group{Name: f[0], GID: gid, Members: members})
	}
	return out, nil
}

// HomeDirs returns the distinct home directories of all accounts. Attackers
// plant SSH keys in service accounts too, so no UID filter is applied.
func (h *Host) HomeDirs() []string {
	users, err := h.Users()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, u := range users {
		switch u.Home {
		case "", "/", "/nonexistent", "/dev/null":
			continue
		}
		if seen[u.Home] {
			continue
		}
		seen[u.Home] = true
		out = append(out, u.Home)
	}
	return out
}
