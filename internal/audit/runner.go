package audit

import (
	"cmp"
	"context"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/host"
)

// HostInfo describes the scanned host.
type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	Root     string `json:"root"`
}

// CheckStatus records a check that was skipped or failed.
type CheckStatus struct {
	CheckID string `json:"check_id"`
	Reason  string `json:"reason"`
}

// Report is the result of running a set of checks against one host.
type Report struct {
	Tool       string         `json:"tool"`
	Version    string         `json:"version"`
	Host       HostInfo       `json:"host"`
	StartedAt  time.Time      `json:"started_at"`
	DurationMS int64          `json:"duration_ms"`
	Score      int            `json:"score"`
	Grade      string         `json:"grade"`
	Summary    map[string]int `json:"summary"`
	ChecksRun  int            `json:"checks_run"`
	Findings   []Finding      `json:"findings"`
	Suppressed int            `json:"suppressed"`
	Skipped    []CheckStatus  `json:"skipped,omitempty"`
	Errors     []CheckStatus  `json:"errors,omitempty"`
}

// Options tunes a Run.
type Options struct {
	Version     string
	Concurrency int
	// Suppress, if non-nil, marks findings as accepted (excluded from score
	// and fail-on thresholds, still present in the report).
	Suppress func(Finding) bool
}

type checkResult struct {
	findings []Finding
	err      error
}

// Run executes checks concurrently against h and assembles a Report. A failing
// check never aborts the run; its error is recorded in Report.Errors.
func Run(ctx context.Context, h *host.Host, checks []Check, opts Options) *Report {
	start := h.Now()
	workers := opts.Concurrency
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}

	results := make([]checkResult, len(checks))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(workers, max(len(checks), 1)) {
		wg.Go(func() {
			for i := range jobs {
				results[i] = runOne(ctx, h, checks[i])
			}
		})
	}
	for i := range checks {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	rep := &Report{
		Tool:      "hostwarden",
		Version:   opts.Version,
		Host:      describeHost(h),
		StartedAt: start.UTC(),
		ChecksRun: len(checks),
		Findings:  []Finding{},
	}
	for i, c := range checks {
		r := results[i]
		if r.err != nil {
			if reason, ok := IsSkip(r.err); ok {
				rep.Skipped = append(rep.Skipped, CheckStatus{CheckID: c.ID, Reason: reason})
			} else {
				rep.Errors = append(rep.Errors, CheckStatus{CheckID: c.ID, Reason: r.err.Error()})
			}
		}
		for _, f := range r.findings {
			f = complete(c, f)
			if opts.Suppress != nil && opts.Suppress(f) {
				f.Suppressed = true
			}
			rep.Findings = append(rep.Findings, f)
		}
	}
	SortFindings(rep.Findings)
	rep.Rescore()
	rep.DurationMS = h.Now().Sub(start).Milliseconds()
	return rep
}

func runOne(ctx context.Context, h *host.Host, c Check) (res checkResult) {
	defer func() {
		if p := recover(); p != nil {
			res = checkResult{err: fmt.Errorf("check panicked: %v", p)}
		}
	}()
	if err := ctx.Err(); err != nil {
		return checkResult{err: err}
	}
	f, err := c.Run(ctx, h)
	return checkResult{findings: f, err: err}
}

func complete(c Check, f Finding) Finding {
	f.CheckID = c.ID
	f.Title = c.Title
	f.Category = c.Category
	if f.Severity == SeverityUnset {
		f.Severity = c.Severity
	}
	if f.Remediation == "" {
		f.Remediation = c.Remediation
	}
	if f.Fix == "" {
		f.Fix = c.Fix
	}
	if f.Message == "" {
		f.Message = c.Title
	}
	f.Fingerprint = Fingerprint(c.ID, f.Target)
	return f
}

// SortFindings orders findings by severity (descending), then check ID, then target.
func SortFindings(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.CheckID, b.CheckID),
			cmp.Compare(a.Target, b.Target),
		)
	})
}

// Severity weights used for scoring. A host starts at 100 and loses points
// per active (non-suppressed) finding, floored at 0.
var severityWeight = map[Severity]int{Critical: 25, High: 10, Medium: 4, Low: 1}

// Rescore recomputes Score, Grade, Summary and Suppressed from Findings.
func (r *Report) Rescore() {
	r.Summary = map[string]int{}
	for s := Info; s <= Critical; s++ {
		r.Summary[s.String()] = 0
	}
	r.Suppressed = 0
	penalty := 0
	for _, f := range r.Findings {
		if f.Suppressed {
			r.Suppressed++
			continue
		}
		r.Summary[f.Severity.String()]++
		penalty += severityWeight[f.Severity]
	}
	r.Score = max(100-penalty, 0)
	r.Grade = Grade(r.Score)
}

// Grade maps a 0-100 score to a letter grade.
func Grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 65:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// Exceeds reports whether any active finding is at or above threshold.
// A SeverityUnset threshold never fails.
func (r *Report) Exceeds(threshold Severity) bool {
	if threshold == SeverityUnset {
		return false
	}
	for _, f := range r.Findings {
		if !f.Suppressed && f.Severity >= threshold {
			return true
		}
	}
	return false
}

// Active returns the non-suppressed findings.
func (r *Report) Active() []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !f.Suppressed {
			out = append(out, f)
		}
	}
	return out
}

func describeHost(h *host.Host) HostInfo {
	return HostInfo{
		Hostname: h.Hostname(),
		OS:       h.OSRelease()["PRETTY_NAME"],
		Kernel:   h.KernelRelease(),
		Root:     h.Root,
	}
}
