package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

func write(t *testing.T, v any) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "b.json")
	b, _ := json.Marshal(v)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMatcher(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	f := File{Version: 1, Accepted: []Entry{
		{Fingerprint: audit.Fingerprint("HW-SSH-001", "/etc/ssh/sshd_config"), Reason: "bastion"},
		{CheckID: "HW-CTR-006", Reason: "legacy images"},
		{CheckID: "HW-FS-002", Target: "/opt/vendor/*", Reason: "vendor agent"},
		{CheckID: "HW-KRN-001", Expires: "2026-05-31", Reason: "expired"},
		{CheckID: "HW-KRN-004", Expires: "2026-06-01", Reason: "today still valid"},
	}}
	m := f.Matcher(now)
	tests := []struct {
		id, target string
		want       bool
	}{
		{"HW-SSH-001", "/etc/ssh/sshd_config", true},
		{"HW-SSH-001", "/etc/ssh/sshd_config.d/x.conf", false},
		{"HW-CTR-006", "container:anything", true},
		{"HW-FS-002", "/opt/vendor/agent", true},
		{"HW-FS-002", "/tmp/agent", false},
		{"HW-KRN-001", "kernel.dmesg_restrict", false},
		{"HW-KRN-004", "/run/reboot-required", true},
	}
	for _, tc := range tests {
		fd := audit.Finding{CheckID: tc.id, Target: tc.target, Fingerprint: audit.Fingerprint(tc.id, tc.target)}
		if got := m(fd); got != tc.want {
			t.Errorf("%s %s matched = %v, want %v", tc.id, tc.target, got, tc.want)
		}
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		v       any
		wantErr bool
	}{
		{"valid", File{Version: 1, Accepted: []Entry{{CheckID: "HW-ACC-004", Reason: "x"}}}, false},
		{"bad version", File{Version: 2}, true},
		{"empty entry", File{Version: 1, Accepted: []Entry{{Reason: "x"}}}, true},
		{"bad glob", File{Version: 1, Accepted: []Entry{{CheckID: "X", Target: "[", Reason: "x"}}}, true},
		{"bad date", File{Version: 1, Accepted: []Entry{{CheckID: "X", Expires: "tomorrow", Reason: "x"}}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(write(t, tc.v))
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file should error")
	}
}

func TestFromReportRoundTrip(t *testing.T) {
	t.Parallel()
	r := &audit.Report{Findings: []audit.Finding{
		{CheckID: "A", Target: "x", Fingerprint: audit.Fingerprint("A", "x")},
		{CheckID: "B", Target: "y", Fingerprint: audit.Fingerprint("B", "y"), Suppressed: true},
	}}
	f := FromReport(r, "initial")
	if len(f.Accepted) != 1 {
		t.Fatalf("accepted = %+v", f.Accepted)
	}
	loaded, err := Load(write(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Matcher(time.Now())(r.Findings[0]) {
		t.Error("baseline should accept its own findings")
	}
}

func TestExampleBaseline(t *testing.T) {
	t.Parallel()
	if _, err := Load(filepath.Join("..", "..", "examples", "baseline.json")); err != nil {
		t.Fatal(err)
	}
}
