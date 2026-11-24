package audit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

func fixed(findings ...audit.Finding) func(context.Context, *host.Host) ([]audit.Finding, error) {
	return func(context.Context, *host.Host) ([]audit.Finding, error) { return findings, nil }
}

func TestRun(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	h := host.New(host.Config{Root: t.TempDir(), Now: func() time.Time { return now }})
	cks := []audit.Check{
		{ID: "T-1", Title: "one", Severity: audit.High, Remediation: "fix one", Run: fixed(audit.Finding{Target: "a"}, audit.Finding{Target: "b", Severity: audit.Low})},
		{ID: "T-2", Title: "two", Severity: audit.Critical, Run: fixed(audit.Finding{Target: "c"})},
		{ID: "T-3", Title: "skip", Severity: audit.Low, Run: func(context.Context, *host.Host) ([]audit.Finding, error) {
			return nil, audit.Skip("not here")
		}},
		{ID: "T-4", Title: "err", Severity: audit.Low, Run: func(context.Context, *host.Host) ([]audit.Finding, error) {
			return nil, errors.New("boom")
		}},
		{ID: "T-5", Title: "panic", Severity: audit.Low, Run: func(context.Context, *host.Host) ([]audit.Finding, error) {
			panic("oops")
		}},
	}
	suppressB := func(f audit.Finding) bool { return f.Target == "b" }
	r := audit.Run(context.Background(), h, cks, audit.Options{Version: "v", Concurrency: 3, Suppress: suppressB})

	if len(r.Findings) != 3 {
		t.Fatalf("findings = %d", len(r.Findings))
	}
	if r.Findings[0].CheckID != "T-2" || r.Findings[1].Target != "a" || r.Findings[2].Target != "b" {
		t.Errorf("unexpected order: %+v", r.Findings)
	}
	a := r.Findings[1]
	if a.Severity != audit.High || a.Remediation != "fix one" || a.Message != "one" || a.Fingerprint != audit.Fingerprint("T-1", "a") {
		t.Errorf("metadata not completed: %+v", a)
	}
	if !r.Findings[2].Suppressed || r.Suppressed != 1 {
		t.Errorf("suppression not applied")
	}
	if r.Score != 100-25-10 || r.Grade != "C" {
		t.Errorf("score = %d %s", r.Score, r.Grade)
	}
	if r.Summary["low"] != 0 || r.Summary["critical"] != 1 {
		t.Errorf("summary = %v", r.Summary)
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Reason != "not here" {
		t.Errorf("skipped = %+v", r.Skipped)
	}
	if len(r.Errors) != 2 {
		t.Errorf("errors = %+v", r.Errors)
	}
	if !r.Exceeds(audit.Critical) || r.Exceeds(audit.SeverityUnset) {
		t.Error("Exceeds wrong")
	}
	r.Findings[0].Suppressed = true
	r.Rescore()
	if r.Exceeds(audit.Critical) || !r.Exceeds(audit.High) {
		t.Error("suppressed findings must not trip thresholds")
	}
}

func TestSeverity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in      string
		want    audit.Severity
		wantErr bool
	}{
		{"critical", audit.Critical, false},
		{" HIGH ", audit.High, false},
		{"info", audit.Info, false},
		{"", audit.SeverityUnset, true},
		{"severe", audit.SeverityUnset, true},
	} {
		got, err := audit.ParseSeverity(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseSeverity(%q) = %v, %v", tc.in, got, err)
		}
	}
	b, _ := audit.Medium.MarshalText()
	var s audit.Severity
	if err := s.UnmarshalText(b); err != nil || s != audit.Medium {
		t.Errorf("round trip = %v, %v", s, err)
	}
}

func TestGrade(t *testing.T) {
	t.Parallel()
	for score, want := range map[int]string{100: "A", 90: "A", 85: "B", 70: "C", 55: "D", 10: "F"} {
		if got := audit.Grade(score); got != want {
			t.Errorf("Grade(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	t.Parallel()
	if got := audit.ShellQuote(`it's`); got != `'it'\''s'` {
		t.Errorf("got %s", got)
	}
}
