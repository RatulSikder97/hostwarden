// Package audit defines the hostwarden check framework: checks, findings,
// severities, and the runner that executes checks against a host.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/host"
)

// Severity ranks how urgently a finding needs attention.
type Severity int

// Severities in ascending order. The zero value means "inherit from the check".
const (
	SeverityUnset Severity = iota
	Info
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"", "info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity parses a severity name (case-insensitive).
func ParseSeverity(name string) (Severity, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	for i, v := range severityNames {
		if i > 0 && v == n {
			return Severity(i), nil
		}
	}
	return SeverityUnset, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", name)
}

// Category groups checks by domain.
type Category string

// Check categories.
const (
	CategorySSH         Category = "ssh"
	CategoryAccounts    Category = "accounts"
	CategoryNetwork     Category = "network"
	CategoryFilesystem  Category = "filesystem"
	CategoryContainer   Category = "container"
	CategoryCompromise  Category = "compromise"
	CategoryKernel      Category = "kernel"
	CategoryMaintenance Category = "maintenance"
)

// Check is a single pluggable audit rule. Run inspects the host read-only and
// returns zero or more findings; the runner fills in metadata from the Check.
type Check struct {
	ID          string
	Title       string
	Category    Category
	Severity    Severity
	Rationale   string
	Remediation string
	// Fix is a generic shell snippet printed by `hostwarden fix`. Findings may
	// override it with a target-specific snippet.
	Fix        string
	References []string
	Run        func(ctx context.Context, h *host.Host) ([]Finding, error)
}

// Finding is one concrete problem discovered on a host.
type Finding struct {
	CheckID     string   `json:"check_id"`
	Title       string   `json:"title"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Target      string   `json:"target"`
	Message     string   `json:"message"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation"`
	Fix         string   `json:"fix,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Suppressed  bool     `json:"suppressed,omitempty"`
}

// Fingerprint returns a stable identifier for a (check, target) pair so a
// finding can be tracked across scans and suppressed by a baseline.
func Fingerprint(checkID, target string) string {
	sum := sha256.Sum256([]byte(checkID + "\x00" + target))
	return hex.EncodeToString(sum[:8])
}

// SkipError reports that a check does not apply to the host (for example,
// Docker checks on a host without Docker).
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return "skipped: " + e.Reason }

// Skip returns a SkipError with a formatted reason.
func Skip(format string, args ...any) error {
	return &SkipError{Reason: fmt.Sprintf(format, args...)}
}

// IsSkip reports whether err is (or wraps) a SkipError, returning the reason.
func IsSkip(err error) (string, bool) {
	var s *SkipError
	if errors.As(err, &s) {
		return s.Reason, true
	}
	return "", false
}

// ShellQuote single-quotes s for safe inclusion in generated fix scripts.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
