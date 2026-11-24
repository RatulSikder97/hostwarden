// Package baseline loads and writes accepted-risk files that suppress known
// findings so CI only fails on new problems.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"slices"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

// Entry accepts one finding (by fingerprint) or a class of findings (by check
// ID plus an optional target glob).
type Entry struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	CheckID     string `json:"check_id,omitempty"`
	Target      string `json:"target,omitempty"`
	Reason      string `json:"reason"`
	// Expires, if set, stops the suppression after the given date (YYYY-MM-DD).
	Expires string `json:"expires,omitempty"`
}

// File is the on-disk baseline format.
type File struct {
	Version   int     `json:"version"`
	Generated string  `json:"generated,omitempty"`
	Accepted  []Entry `json:"accepted"`
}

// Load reads and validates a baseline file.
func Load(p string) (*File, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", p, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("baseline %s: unsupported version %d", p, f.Version)
	}
	for i, e := range f.Accepted {
		if e.Fingerprint == "" && e.CheckID == "" {
			return nil, fmt.Errorf("baseline %s: entry %d needs a fingerprint or check_id", p, i)
		}
		if e.Target != "" {
			if _, err := path.Match(e.Target, ""); err != nil {
				return nil, fmt.Errorf("baseline %s: entry %d: bad target glob %q: %w", p, i, e.Target, err)
			}
		}
		if e.Expires != "" {
			if _, err := time.Parse(time.DateOnly, e.Expires); err != nil {
				return nil, fmt.Errorf("baseline %s: entry %d: expires must be YYYY-MM-DD: %w", p, i, err)
			}
		}
	}
	return &f, nil
}

// Matcher returns a predicate reporting whether a finding is accepted as of now.
func (f *File) Matcher(now time.Time) func(audit.Finding) bool {
	return func(fd audit.Finding) bool {
		return slices.ContainsFunc(f.Accepted, func(e Entry) bool { return e.matches(fd, now) })
	}
}

func (e Entry) matches(fd audit.Finding, now time.Time) bool {
	if e.Expires != "" {
		exp, err := time.Parse(time.DateOnly, e.Expires)
		if err != nil || !now.Before(exp.Add(24*time.Hour)) {
			return false
		}
	}
	if e.Fingerprint != "" {
		return e.Fingerprint == fd.Fingerprint
	}
	if e.CheckID != fd.CheckID {
		return false
	}
	if e.Target == "" {
		return true
	}
	ok, _ := path.Match(e.Target, fd.Target)
	return ok
}

// FromReport builds a baseline accepting every active finding in r.
func FromReport(r *audit.Report, reason string) *File {
	f := &File{Version: 1, Generated: r.StartedAt.Format(time.RFC3339), Accepted: []Entry{}}
	for _, fd := range r.Active() {
		f.Accepted = append(f.Accepted, Entry{
			Fingerprint: fd.Fingerprint,
			CheckID:     fd.CheckID,
			Target:      fd.Target,
			Reason:      reason,
		})
	}
	return f
}
