// Package host gives checks read-only access to a Linux host rooted at an
// arbitrary directory, so every check can run against a live system ("/") or a
// fixture tree in tests.
package host

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ContainerLister lists containers with their runtime configuration.
type ContainerLister interface {
	Containers(ctx context.Context) ([]Container, error)
}

// Container is the subset of container state hostwarden audits.
type Container struct {
	ID          string
	Name        string
	Image       string
	User        string
	Privileged  bool
	NetworkMode string
	PidMode     string
	CapAdd      []string
	Mounts      []Mount
}

// Mount is a bind or volume mount inside a container.
type Mount struct {
	Source      string
	Destination string
	ReadWrite   bool
}

// Executor runs a read-only probe command (for example `apt-get -s upgrade`).
// It is only wired up when scanning the live root filesystem.
type Executor interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Config configures a Host.
type Config struct {
	// Root is the filesystem root to audit. Defaults to "/".
	Root string
	// Proc is the procfs mount to read. Defaults to "/proc" for a live root
	// and "<root>/proc" otherwise.
	Proc string
	// RecentWindow is how far back "recently modified" indicators look.
	RecentWindow time.Duration
	// Now returns the current time; defaults to time.Now.
	Now func() time.Time
	// Docker lists containers; nil disables Docker API checks.
	Docker ContainerLister
	// Exec runs probe commands; nil disables command-based probes.
	Exec Executor
}

// Host is a read-only view of a Linux system.
type Host struct {
	Root         string
	Proc         string
	RecentWindow time.Duration
	Docker       ContainerLister
	Exec         Executor
	now          func() time.Time

	scanOnce sync.Once
	scan     *FileScan
	scanErr  error

	procOnce sync.Once
	procs    []Process
	procErr  error
}

// New builds a Host from cfg, applying defaults.
func New(cfg Config) *Host {
	root := cfg.Root
	if root == "" {
		root = "/"
	}
	root = filepath.Clean(root)
	proc := cfg.Proc
	if proc == "" {
		proc = filepath.Join(root, "proc")
	}
	window := cfg.RecentWindow
	if window <= 0 {
		window = 72 * time.Hour
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Host{
		Root:         root,
		Proc:         filepath.Clean(proc),
		RecentWindow: window,
		Docker:       cfg.Docker,
		Exec:         cfg.Exec,
		now:          now,
	}
}

// Live reports whether the host is the running system's own root.
func (h *Host) Live() bool { return h.Root == "/" }

// Now returns the host clock.
func (h *Host) Now() time.Time { return h.now() }

// Path maps an absolute host path into the audited root.
func (h *Host) Path(p string) string {
	return filepath.Join(h.Root, filepath.FromSlash(p))
}

// ProcPath maps a path relative to procfs.
func (h *Host) ProcPath(p string) string {
	return filepath.Join(h.Proc, filepath.FromSlash(p))
}

// Rel converts a real filesystem path under Root back into a host path.
func (h *Host) Rel(real string) string {
	rel, err := filepath.Rel(h.Root, real)
	if err != nil || strings.HasPrefix(rel, "..") {
		return real
	}
	return "/" + filepath.ToSlash(rel)
}

// ReadFile reads a host path.
func (h *Host) ReadFile(p string) ([]byte, error) { return os.ReadFile(h.Path(p)) }

// Lstat stats a host path without following symlinks.
func (h *Host) Lstat(p string) (fs.FileInfo, error) { return os.Lstat(h.Path(p)) }

// Stat stats a host path.
func (h *Host) Stat(p string) (fs.FileInfo, error) { return os.Stat(h.Path(p)) }

// Exists reports whether a host path exists.
func (h *Host) Exists(p string) bool {
	_, err := os.Lstat(h.Path(p))
	return err == nil
}

// Glob expands a host glob pattern and returns host paths, sorted.
func (h *Host) Glob(pattern string) []string {
	matches, err := filepath.Glob(h.Path(pattern))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, h.Rel(m))
	}
	return out
}

// Line is one line of a file with its 1-based number.
type Line struct {
	N    int
	Text string
}

// Lines reads a host file and returns its lines. Missing files return
// fs.ErrNotExist (test with errors.Is).
func (h *Host) Lines(p string) ([]Line, error) {
	b, err := h.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return splitLines(b), nil
}

func splitLines(b []byte) []Line {
	var out []Line
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		out = append(out, Line{N: n, Text: sc.Text()})
	}
	return out
}

// Hostname returns the host name from procfs (live) or /etc/hostname.
func (h *Host) Hostname() string {
	if b, err := os.ReadFile(h.ProcPath("sys/kernel/hostname")); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	if b, err := h.ReadFile("/etc/hostname"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "unknown"
}

// KernelRelease returns the running kernel release, if procfs is available.
func (h *Host) KernelRelease() string {
	b, err := os.ReadFile(h.ProcPath("sys/kernel/osrelease"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// OSRelease parses /etc/os-release (falling back to /usr/lib/os-release).
func (h *Host) OSRelease() map[string]string {
	out := map[string]string{}
	b, err := h.ReadFile("/etc/os-release")
	if err != nil {
		if b, err = h.ReadFile("/usr/lib/os-release"); err != nil {
			return out
		}
	}
	for _, l := range splitLines(b) {
		k, v, ok := strings.Cut(strings.TrimSpace(l.Text), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

// OSFamily returns "debian", "rhel", "alpine", or "" when unknown.
func (h *Host) OSFamily() string {
	rel := h.OSRelease()
	ids := strings.Fields(rel["ID"] + " " + rel["ID_LIKE"])
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu":
			return "debian"
		case "rhel", "fedora", "centos", "rocky", "almalinux", "amzn":
			return "rhel"
		case "alpine":
			return "alpine"
		}
	}
	return ""
}

// ReadSysctl reads a sysctl value (dotted key) from procfs.
func (h *Host) ReadSysctl(key string) (string, error) {
	b, err := os.ReadFile(h.ProcPath("sys/" + strings.ReplaceAll(key, ".", "/")))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// IsNotExist reports whether err means a path is absent.
func IsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
