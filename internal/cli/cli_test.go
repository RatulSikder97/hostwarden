package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/testutil"
)

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, IO{Stdout: &out, Stderr: &errb})
	return code, out.String(), errb.String()
}

func TestScanExitCodesAndFormats(t *testing.T) {
	t.Parallel()
	root := testutil.Fixture(t, "compromised")
	clean := testutil.Fixture(t, "hardened")
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
	}{
		{"table default never fails", []string{"scan", "--root", root}, ExitOK, "Score 0/100 (F)"},
		{"fail on high", []string{"scan", "--root", root, "--fail-on", "high", "--format", "json"}, ExitFindings, `"check_id": "HW-IOC-007"`},
		{"hardened passes fail-on low", []string{"scan", "--root", clean, "--fail-on", "low"}, ExitOK, "No findings."},
		{"sarif", []string{"scan", "--root", root, "--format", "sarif", "--checks", "HW-IOC"}, ExitOK, `"version": "2.1.0"`},
		{"select by category", []string{"scan", "--root", root, "--checks", "ssh", "--fail-on", "critical"}, ExitOK, "HW-SSH-001"},
		{"bad severity", []string{"scan", "--fail-on", "severe"}, ExitError, ""},
		{"bad format", []string{"scan", "--format", "xml"}, ExitError, ""},
		{"bad selector", []string{"scan", "--root", root, "--checks", "HW-NOPE"}, ExitError, ""},
		{"stray args", []string{"scan", "extra"}, ExitError, ""},
		{"help", []string{"scan", "-h"}, ExitOK, ""},
		{"unknown command", []string{"frobnicate"}, ExitError, ""},
		{"no command", nil, ExitError, ""},
		{"version", []string{"--version"}, ExitOK, "hostwarden "},
		{"checks markdown", []string{"checks", "--format", "markdown"}, ExitOK, "| `HW-IOC-011` | high | compromise |"},
		{"checks json", []string{"checks", "--format", "json"}, ExitOK, `"id": "HW-SSH-001"`},
		{"serve needs --metrics", []string{"serve"}, ExitError, ""},
		{"fleet needs inventory", []string{"fleet"}, ExitError, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, out, stderr := run(t, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit = %d, want %d\nstderr: %s", code, tc.wantCode, stderr)
			}
			if !strings.Contains(out, tc.wantOut) {
				t.Errorf("stdout missing %q:\n%s", tc.wantOut, out)
			}
		})
	}
}

func TestBaselineWorkflow(t *testing.T) {
	t.Parallel()
	root := testutil.Fixture(t, "compromised")
	bl := filepath.Join(t.TempDir(), "baseline.json")

	code, _, stderr := run(t, "baseline", "--root", root, "--checks", "kernel,accounts", "-o", bl, "--reason", "legacy fleet")
	if code != ExitOK {
		t.Fatalf("baseline exit %d: %s", code, stderr)
	}
	code, out, _ := run(t, "scan", "--root", root, "--checks", "kernel,accounts", "--baseline", bl, "--fail-on", "low", "--format", "json")
	if code != ExitOK {
		t.Fatalf("scan with baseline should pass, got %d", code)
	}
	var rep audit.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Suppressed == 0 || len(rep.Active()) != 0 || rep.Score != 100 {
		t.Errorf("suppressed=%d active=%d score=%d", rep.Suppressed, len(rep.Active()), rep.Score)
	}
	// A new class of finding still fails CI.
	code, _, _ = run(t, "scan", "--root", root, "--baseline", bl, "--fail-on", "high")
	if code != ExitFindings {
		t.Errorf("new findings must fail, got %d", code)
	}
	// Extending the baseline keeps old entries.
	code, _, _ = run(t, "baseline", "--root", root, "--checks", "ssh", "--baseline", bl, "-o", bl)
	if code != ExitOK {
		t.Fatal("extend baseline failed")
	}
	b, _ := os.ReadFile(bl)
	if !strings.Contains(string(b), "HW-ACC-001") || !strings.Contains(string(b), "HW-SSH-001") {
		t.Errorf("extended baseline lost entries:\n%s", b)
	}
}

func TestFixAndOutputFile(t *testing.T) {
	t.Parallel()
	root := testutil.Fixture(t, "compromised")
	code, out, _ := run(t, "fix", "--root", root, "--checks", "HW-FS-004,HW-IOC-007")
	if code != ExitOK {
		t.Fatalf("fix exit %d", code)
	}
	for _, want := range []string{"chmod 640 /etc/shadow", "# kill -9 4242", "NOT executed"} {
		if !strings.Contains(out, want) {
			t.Errorf("fix script missing %q", want)
		}
	}
	dst := filepath.Join(t.TempDir(), "r.sarif")
	code, _, stderr := run(t, "scan", "--root", root, "--format", "sarif", "--output", dst)
	if code != ExitOK || !strings.Contains(stderr, "wrote sarif report") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if b, err := os.ReadFile(dst); err != nil || !json.Valid(b) {
		t.Errorf("sarif file invalid: %v", err)
	}
}

func TestBinaryFlag(t *testing.T) {
	t.Parallel()
	b := binaryFlag{}
	if err := b.Set("dist/hw"); err != nil || b["amd64"] != "dist/hw" || b["arm64"] != "dist/hw" {
		t.Errorf("single path: %v %v", b, err)
	}
	if err := b.Set("arm64=dist/arm"); err != nil || b["arm64"] != "dist/arm" {
		t.Errorf("arch path: %v %v", b, err)
	}
	if err := b.Set("riscv64=x"); err == nil {
		t.Error("unsupported arch accepted")
	}
}
