// Package testutil builds throwaway host filesystems for check tests. Git does
// not preserve permission bits, symlink-heavy procfs layouts or mtimes, so
// fixtures are copied into a temp dir and finished from a manifest.
package testutil

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/host"
)

// DefaultAge is the mtime age applied to every fixture file so that only the
// files a test marks as recent trip "recently modified" checks.
const DefaultAge = 400 * 24 * time.Hour

// File describes one entry in a Tree.
type File struct {
	Content string
	Mode    uint32 // chmod-style octal incl. 04000/02000/01000; 0 means 0644 (0755 for dirs)
	Link    string // if set, create a symlink with this target instead
	Dir     bool
	Age     time.Duration // mtime age; 0 means DefaultAge
}

// Tree maps slash-separated paths (relative to the fake root) to entries.
// Paths under "proc/" form the fake procfs.
type Tree map[string]File

// Build materialises tree in a temp dir and returns the root path.
func Build(t testing.TB, tree Tree) string {
	t.Helper()
	root := t.TempDir()
	now := time.Now()
	for p, f := range tree {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		switch {
		case f.Link != "":
			if err := os.Symlink(f.Link, full); err != nil {
				t.Fatal(err)
			}
			continue
		case f.Dir:
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
		default:
			if err := os.WriteFile(full, []byte(f.Content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if f.Mode != 0 {
			chmod(t, full, octalToMode(f.Mode))
		}
		age := f.Age
		if age == 0 {
			age = DefaultAge
		}
		mt := now.Add(-age)
		if err := os.Chtimes(full, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// Host returns a Host for a root built by Build or Fixture.
func Host(root string) *host.Host {
	return host.New(host.Config{Root: root, Proc: filepath.Join(root, "proc")})
}

// RepoRoot returns the repository root directory.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// Fixture copies testdata/fixtures/<name> into a temp dir, ages every file by
// DefaultAge and applies testdata/fixtures/<name>.manifest. Manifest lines:
//
//	mode 0640 etc/shadow           # chmod (octal, supports 4000/2000/1000 bits)
//	dir  1777 tmp                  # mkdir + chmod (git drops empty dirs)
//	link proc/42/exe /tmp/x (deleted)  # symlink; the target is the rest of the line
//	age  2h usr/bin/ps             # set mtime to now-2h
func Fixture(t testing.TB, name string) string {
	t.Helper()
	src := filepath.Join(RepoRoot(), "testdata", "fixtures", name)
	dst := t.TempDir()
	old := time.Now().Add(-DefaultAge)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			return err
		}
		return os.Chtimes(target, old, old)
	})
	if err != nil {
		t.Fatalf("copy fixture %s: %v", name, err)
	}
	applyManifest(t, dst, filepath.Join(RepoRoot(), "testdata", "fixtures", name+".manifest"))
	return dst
}

func applyManifest(t testing.TB, root, manifest string) {
	t.Helper()
	f, err := os.Open(manifest)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			t.Fatalf("%s:%d: malformed line %q", manifest, n, line)
		}
		op, a, b := parts[0], strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		switch op {
		case "mode", "dir":
			mode, err := strconv.ParseUint(a, 8, 32)
			if err != nil {
				t.Fatalf("%s:%d: %v", manifest, n, err)
			}
			full := filepath.Join(root, filepath.FromSlash(b))
			if op == "dir" {
				if err := os.MkdirAll(full, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			chmod(t, full, octalToMode(uint32(mode)))
		case "link":
			linkPath, target, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "link")), " ")
			if !ok {
				t.Fatalf("%s:%d: link needs a path and a target", manifest, n)
			}
			full := filepath.Join(root, filepath.FromSlash(linkPath))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(strings.TrimSpace(target), full); err != nil {
				t.Fatal(err)
			}
		case "age":
			d, err := time.ParseDuration(a)
			if err != nil {
				t.Fatalf("%s:%d: %v", manifest, n, err)
			}
			mt := time.Now().Add(-d)
			if err := os.Chtimes(filepath.Join(root, filepath.FromSlash(b)), mt, mt); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("%s:%d: unknown op %q", manifest, n, op)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}

// octalToMode converts a chmod-style octal (e.g. 04755) into an fs.FileMode.
func octalToMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

func chmod(t testing.TB, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}
