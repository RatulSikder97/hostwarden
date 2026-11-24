// Package checks assembles the built-in check catalogue.
package checks

import (
	"fmt"
	"slices"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/checks/accounts"
	"github.com/RatulSikder97/hostwarden/internal/checks/compromise"
	"github.com/RatulSikder97/hostwarden/internal/checks/container"
	"github.com/RatulSikder97/hostwarden/internal/checks/filesystem"
	"github.com/RatulSikder97/hostwarden/internal/checks/kernel"
	"github.com/RatulSikder97/hostwarden/internal/checks/network"
	"github.com/RatulSikder97/hostwarden/internal/checks/ssh"
)

// All returns every built-in check in catalogue order.
func All() []audit.Check {
	var out []audit.Check
	for _, group := range [][]audit.Check{
		ssh.Checks(),
		accounts.Checks(),
		network.Checks(),
		filesystem.Checks(),
		container.Checks(),
		compromise.Checks(),
		kernel.Checks(),
	} {
		out = append(out, group...)
	}
	return out
}

// Select filters checks. include and exclude hold check IDs, ID prefixes
// (e.g. "HW-SSH") or category names (e.g. "compromise"); an empty include
// selects everything. Unknown selectors are reported as an error.
func Select(all []audit.Check, include, exclude []string) ([]audit.Check, error) {
	matches := func(c audit.Check, sel string) bool {
		sel = strings.TrimSpace(sel)
		return strings.EqualFold(c.ID, sel) ||
			strings.HasPrefix(strings.ToUpper(c.ID), strings.ToUpper(sel)+"-") ||
			strings.EqualFold(string(c.Category), sel)
	}
	for _, sel := range slices.Concat(include, exclude) {
		if !slices.ContainsFunc(all, func(c audit.Check) bool { return matches(c, sel) }) {
			return nil, fmt.Errorf("unknown check selector %q", sel)
		}
	}
	var out []audit.Check
	for _, c := range all {
		if len(include) > 0 && !slices.ContainsFunc(include, func(s string) bool { return matches(c, s) }) {
			continue
		}
		if slices.ContainsFunc(exclude, func(s string) bool { return matches(c, s) }) {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}
