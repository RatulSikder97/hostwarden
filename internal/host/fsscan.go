package host

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FileEntry is a path and its mode captured during the filesystem walk.
type FileEntry struct {
	Path string // host path
	Mode fs.FileMode
}

// FileScan is the result of one bounded walk over the host filesystem, shared
// by every filesystem check so the tree is traversed once per scan.
type FileScan struct {
	// WorldWritableDirs lists o+w directories without the sticky bit.
	WorldWritableDirs []FileEntry
	// SetID lists regular files with the setuid or setgid bit.
	SetID []FileEntry
	// ExposedPrivateKeys lists PEM/OpenSSH private keys readable by group or other.
	ExposedPrivateKeys []FileEntry
}

// prunedDirs are never descended into: pseudo filesystems, container
// storage (audited via the Docker API instead) and removable media.
var prunedDirs = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true, "/run": true,
	"/var/lib/docker": true, "/var/lib/containerd": true, "/var/lib/containers": true,
	"/var/lib/kubelet": true, "/var/lib/desktop-containerd": true, "/var/lib/rancher": true,
	"/var/lib/lxc": true, "/var/lib/lxd": true, "/snap": true, "/mnt": true, "/media": true, "/lost+found": true,
}

// alwaysWalked are re-included even though their parent is pruned.
var alwaysWalked = []string{"/dev/shm", "/run/shm"}

// remoteOrPseudoFS are filesystem types never walked below the root mount:
// network shares, pseudo filesystems and container overlay mounts.
var remoteOrPseudoFS = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "fuse.sshfs": true, "9p": true,
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "devpts": true,
	"debugfs": true, "tracefs": true, "securityfs": true, "bpf": true,
	"overlay": true, "virtiofs": true, "fakeowner": true, "fuse.grpcfuse": true, "vboxsf": true, "fuse.s3fs": true,
	"autofs": true, "binfmt_misc": true, "configfs": true, "fusectl": true,
}

// Files walks the host filesystem once (lazily) and returns the shared scan.
func (h *Host) Files() (*FileScan, error) {
	h.scanOnce.Do(func() { h.scan, h.scanErr = h.walk() })
	return h.scan, h.scanErr
}

func (h *Host) walk() (*FileScan, error) {
	prune := map[string]bool{}
	for p := range prunedDirs {
		prune[p] = true
	}
	// Mount points are reported in the reader's namespace; Rel maps them
	// into the audited root (identity for a live scan).
	if mounts, err := h.Mounts(); err == nil {
		for _, m := range mounts {
			if remoteOrPseudoFS[m.FSType] && m.Point != "/" {
				prune[h.Rel(m.Point)] = true
			}
		}
	}
	// Never walk the procfs we were pointed at, wherever it lives.
	prune[h.Rel(h.Proc)] = true

	scan := &FileScan{}
	visit := func(real string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable subtrees are expected when not running as root.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		hp := h.Rel(real)
		if d.IsDir() {
			if prune[hp] && real != h.Root {
				return fs.SkipDir
			}
		}
		t := d.Type()
		if t&fs.ModeSymlink != 0 || (!t.IsDir() && !t.IsRegular()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		mode := info.Mode()
		switch {
		case mode.IsDir():
			if mode.Perm()&0o002 != 0 && mode&fs.ModeSticky == 0 {
				scan.WorldWritableDirs = append(scan.WorldWritableDirs, FileEntry{Path: hp, Mode: mode})
			}
		case mode.IsRegular():
			if mode&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
				scan.SetID = append(scan.SetID, FileEntry{Path: hp, Mode: mode})
			}
			if mode.Perm()&0o044 != 0 && looksLikeKeyName(d.Name()) && info.Size() < 64<<10 && isPrivateKey(real) {
				scan.ExposedPrivateKeys = append(scan.ExposedPrivateKeys, FileEntry{Path: hp, Mode: mode})
			}
		}
		return nil
	}
	if err := filepath.WalkDir(h.Root, visit); err != nil {
		return nil, err
	}
	for _, extra := range alwaysWalked {
		if fi, err := os.Lstat(h.Path(extra)); err == nil && fi.IsDir() {
			_ = filepath.WalkDir(h.Path(extra), visit)
		}
	}
	return scan, nil
}

func looksLikeKeyName(name string) bool {
	if strings.HasSuffix(name, ".pub") {
		return false
	}
	switch {
	case strings.HasPrefix(name, "id_"),
		strings.HasSuffix(name, "_key"),
		strings.HasSuffix(name, ".key"),
		strings.HasSuffix(name, ".pem"):
		return true
	}
	return false
}

func isPrivateKey(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 128)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	return bytes.Contains(head, []byte("-----BEGIN")) && bytes.Contains(head, []byte("PRIVATE KEY"))
}
