package fleet

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

// Summary aggregates per-host results.
type Summary struct {
	GeneratedAt  time.Time    `json:"generated_at"`
	Hosts        int          `json:"hosts"`
	Failed       int          `json:"failed"`
	AverageScore float64      `json:"average_score"`
	TopChecks    []CheckCount `json:"top_checks"`
	Results      []Result     `json:"results"`
}

// CheckCount counts how many hosts a check fired on.
type CheckCount struct {
	CheckID  string         `json:"check_id"`
	Title    string         `json:"title"`
	Severity audit.Severity `json:"severity"`
	Hosts    int            `json:"hosts"`
}

// Summarize aggregates results.
func Summarize(results []Result, now time.Time) Summary {
	s := Summary{GeneratedAt: now.UTC(), Hosts: len(results), Results: results, TopChecks: []CheckCount{}}
	counts := map[string]*CheckCount{}
	scored := 0
	for _, r := range results {
		if r.Report == nil {
			s.Failed++
			continue
		}
		scored++
		s.AverageScore += float64(r.Report.Score)
		seen := map[string]bool{}
		for _, f := range r.Report.Active() {
			if seen[f.CheckID] {
				continue
			}
			seen[f.CheckID] = true
			c, ok := counts[f.CheckID]
			if !ok {
				c = &CheckCount{CheckID: f.CheckID, Title: f.Title, Severity: f.Severity}
				counts[f.CheckID] = c
			}
			c.Severity = max(c.Severity, f.Severity)
			c.Hosts++
		}
	}
	if scored > 0 {
		s.AverageScore /= float64(scored)
	}
	for _, c := range counts {
		s.TopChecks = append(s.TopChecks, *c)
	}
	slices.SortFunc(s.TopChecks, func(a, b CheckCount) int {
		return cmp.Or(cmp.Compare(b.Severity, a.Severity), cmp.Compare(b.Hosts, a.Hosts), cmp.Compare(a.CheckID, b.CheckID))
	})
	return s
}

// Exceeds reports whether any host has an active finding at or above threshold.
func (s Summary) Exceeds(threshold audit.Severity) bool {
	return slices.ContainsFunc(s.Results, func(r Result) bool { return r.Report != nil && r.Report.Exceeds(threshold) })
}

// WriteJSON writes the summary as JSON.
func (s Summary) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// WriteTable writes a per-host table followed by the most widespread checks.
func (s Summary) WriteTable(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tADDRESS\tSCORE\tCRIT\tHIGH\tMED\tLOW\tSTATUS")
	for _, r := range s.Results {
		if r.Report == nil {
			fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\t-\t-\terror: %s\n", r.Name, r.Address, oneLine(r.Error, 80))
			continue
		}
		sm := r.Report.Summary
		fmt.Fprintf(tw, "%s\t%s\t%d (%s)\t%d\t%d\t%d\t%d\tok\n", r.Name, r.Address, r.Report.Score, r.Report.Grade,
			sm["critical"], sm["high"], sm["medium"], sm["low"])
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n%d hosts · %d failed · average score %.0f\n", s.Hosts, s.Failed, s.AverageScore)
	if len(s.TopChecks) > 0 {
		fmt.Fprintln(w, "\nMost widespread findings:")
		tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for i, c := range s.TopChecks {
			if i == 10 {
				break
			}
			fmt.Fprintf(tw, "  %s\t%s\t%d/%d hosts\t%s\n", strings.ToUpper(c.Severity.String()), c.CheckID, c.Hosts, s.Hosts-s.Failed, c.Title)
		}
		return tw.Flush()
	}
	return nil
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-3] + "..."
	}
	return s
}
