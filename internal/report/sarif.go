package report

import (
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

// SARIF 2.1.0 subset accepted by GitHub code scanning.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool         `json:"tool"`
	AutomationDetails map[string]string `json:"automationDetails,omitempty"`
	Results           []sarifResult     `json:"results"`
	Properties        map[string]any    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      sarifText         `json:"fullDescription"`
	Help                 sarifText         `json:"help"`
	HelpURI              string            `json:"helpUri"`
	DefaultConfiguration map[string]string `json:"defaultConfiguration"`
	Properties           sarifRuleProps    `json:"properties"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
	Precision        string   `json:"precision"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation struct {
		URI string `json:"uri"`
	} `json:"artifactLocation"`
	Region *sarifRegion `json:"region,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

const catalogueURL = "https://github.com/RatulSikder97/hostwarden#check-catalogue"

// SecuritySeverity maps severities onto GitHub's 0-10 security-severity scale.
func SecuritySeverity(s audit.Severity) string {
	switch s {
	case audit.Critical:
		return "9.5"
	case audit.High:
		return "8.0"
	case audit.Medium:
		return "5.5"
	case audit.Low:
		return "3.0"
	default:
		return "0.0"
	}
}

func sarifLevel(s audit.Severity) string {
	switch {
	case s >= audit.High:
		return "error"
	case s == audit.Medium:
		return "warning"
	default:
		return "note"
	}
}

// SARIF writes the report as a SARIF 2.1.0 log. Every check in catalogue
// becomes a rule so code scanning can show rule help for each alert.
func SARIF(w io.Writer, r *audit.Report, catalogue []audit.Check) error {
	rules := make([]sarifRule, 0, len(catalogue))
	index := map[string]int{}
	for i, c := range catalogue {
		index[c.ID] = i
		rules = append(rules, sarifRule{
			ID:                   c.ID,
			Name:                 ruleName(c.Title),
			ShortDescription:     sarifText{c.Title},
			FullDescription:      sarifText{c.Rationale},
			Help:                 sarifText{c.Remediation},
			HelpURI:              catalogueURL,
			DefaultConfiguration: map[string]string{"level": sarifLevel(c.Severity)},
			Properties: sarifRuleProps{
				Tags:             []string{"security", "hostwarden", string(c.Category)},
				SecuritySeverity: SecuritySeverity(c.Severity),
				Precision:        "high",
			},
		})
	}
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		idx, ok := index[f.CheckID]
		if !ok {
			continue
		}
		msg := f.Message
		if len(f.Evidence) > 0 {
			msg += "\n\nEvidence:\n- " + strings.Join(f.Evidence, "\n- ")
		}
		res := sarifResult{
			RuleID:              f.CheckID,
			RuleIndex:           idx,
			Level:               sarifLevel(f.Severity),
			Message:             sarifText{msg},
			Locations:           []sarifLocation{location(r.Host.Hostname, f.Target)},
			PartialFingerprints: map[string]string{"hostwarden/v1": f.Fingerprint},
			Properties: map[string]any{
				"severity":          f.Severity.String(),
				"security-severity": SecuritySeverity(f.Severity),
				"target":            f.Target,
				"host":              r.Host.Hostname,
			},
		}
		if f.Suppressed {
			res.Suppressions = []sarifSuppression{{Kind: "external", Justification: "accepted in hostwarden baseline"}}
		}
		results = append(results, res)
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "hostwarden",
				Version:        r.Version,
				InformationURI: "https://github.com/RatulSikder97/hostwarden",
				Rules:          rules,
			}},
			AutomationDetails: map[string]string{"id": "hostwarden/" + r.Host.Hostname + "/"},
			Results:           results,
			Properties: map[string]any{
				"score": r.Score,
				"grade": r.Grade,
			},
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

var (
	lineSuffix = regexp.MustCompile(`^(/[^#:]*?):(\d+)$`)
	unsafeURI  = regexp.MustCompile(`[^A-Za-z0-9._/-]+`)
)

// location maps a finding target onto a SARIF artifact location. File targets
// keep their path (and line); runtime targets such as "pid:42" or
// "tcp/0.0.0.0:6379" get a synthetic host-scoped URI.
func location(hostname, target string) sarifLocation {
	var loc sarifLocation
	p := target
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	if m := lineSuffix.FindStringSubmatch(p); m != nil {
		p = m[1]
		n, _ := strconv.Atoi(m[2])
		loc.PhysicalLocation.Region = &sarifRegion{StartLine: n}
	}
	if strings.HasPrefix(p, "/") {
		loc.PhysicalLocation.ArtifactLocation.URI = strings.TrimPrefix(p, "/")
		return loc
	}
	loc.PhysicalLocation.ArtifactLocation.URI = "hostwarden/" + unsafeURI.ReplaceAllString(hostname, "_") + "/" + unsafeURI.ReplaceAllString(target, "_")
	return loc
}

func ruleName(title string) string {
	var b strings.Builder
	for w := range strings.FieldsSeq(title) {
		w = unsafeURI.ReplaceAllString(w, "")
		if w == "" {
			continue
		}
		b.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	return b.String()
}
