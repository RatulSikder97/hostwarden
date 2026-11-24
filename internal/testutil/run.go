package testutil

import (
	"context"
	"slices"
	"testing"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

// RunCheck runs the check with the given ID from catalogue against h.
func RunCheck(t testing.TB, catalogue []audit.Check, id string, h *host.Host) ([]audit.Finding, error) {
	t.Helper()
	i := slices.IndexFunc(catalogue, func(c audit.Check) bool { return c.ID == id })
	if i < 0 {
		t.Fatalf("no check %s in catalogue", id)
	}
	return catalogue[i].Run(context.Background(), h)
}

// Targets returns the finding targets in order.
func Targets(fs []audit.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Target)
	}
	return out
}
