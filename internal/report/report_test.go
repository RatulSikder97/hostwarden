package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

func sample() (*audit.Report, []audit.Check) {
	cat := []audit.Check{
		{ID: "HW-SSH-001", Title: "SSH password authentication enabled", Category: audit.CategorySSH, Severity: audit.High, Rationale: "r", Remediation: "m"},
		{ID: "HW-IOC-007", Title: "Crypto-miner process", Category: audit.CategoryCompromise, Severity: audit.Critical, Rationale: "r", Remediation: "m"},
		{ID: "HW-KRN-001", Title: "Kernel sysctl not hardened", Category: audit.CategoryKernel, Severity: audit.Low, Rationale: "r", Remediation: "m"},
	}
	r := &audit.Report{
		Tool: "hostwarden", Version: "1.0.0", StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Host: audit.HostInfo{Hostname: "web-01", OS: "Debian GNU/Linux 12", Root: "/"},
		Findings: []audit.Finding{
			{CheckID: "HW-IOC-007", Title: "Crypto-miner process", Severity: audit.Critical, Target: "pid:4242", Message: "kdevtmpfsi looks like a miner", Evidence: []string{"exe=/tmp/x (deleted)"}, Fix: "# kill -9 4242"},
			{CheckID: "HW-SSH-001", Title: "SSH password authentication enabled", Severity: audit.High, Target: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Message: "effective PasswordAuthentication is \"yes\""},
			{CheckID: "HW-KRN-001", Title: "Kernel sysctl not hardened", Severity: audit.Low, Target: "kernel.dmesg_restrict", Message: "kernel.dmesg_restrict = 0", Suppressed: true, Remediation: "persist it"},
		},
	}
	for i := range r.Findings {
		r.Findings[i].Fingerprint = audit.Fingerprint(r.Findings[i].CheckID, r.Findings[i].Target)
	}
	r.Rescore()
	return r, cat
}

func TestTable(t *testing.T) {
	t.Parallel()
	r, _ := sample()
	var plain, color bytes.Buffer
	if err := Table(&plain, r, TableOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	out := plain.String()
	for _, want := range []string{"CRITICAL  HW-IOC-007", "HW-SSH-001", "· exe=/tmp/x (deleted)", "Score 65/100 (C)", "1 suppressed"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("plain output contains ANSI escapes")
	}
	if strings.Contains(out, "kernel.dmesg_restrict") {
		t.Error("suppressed finding rendered in table")
	}
	_ = Table(&color, r, TableOptions{Color: true})
	if !strings.Contains(color.String(), "\x1b[1;31mCRITICAL") {
		t.Error("color output missing severity styling")
	}
}

func TestJSON(t *testing.T) {
	t.Parallel()
	r, _ := sample()
	var buf bytes.Buffer
	if err := JSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	var back audit.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Findings[0].Severity != audit.Critical || back.Score != r.Score {
		t.Errorf("round trip mismatch: %+v", back.Findings[0])
	}
	if !strings.Contains(buf.String(), `"severity": "critical"`) {
		t.Error("severity should serialise as a string")
	}
}

func TestSARIF(t *testing.T) {
	t.Parallel()
	r, cat := sample()
	var buf bytes.Buffer
	if err := SARIF(&buf, r, cat); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Name       string `json:"name"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Suppressions []json.RawMessage `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", log)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 3 || run.Tool.Driver.Rules[1].Properties.SecuritySeverity != "9.5" || run.Tool.Driver.Rules[0].Name != "SSHPasswordAuthenticationEnabled" {
		t.Errorf("rules = %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d", len(run.Results))
	}
	res := run.Results[0]
	if res.RuleID != "HW-IOC-007" || res.RuleIndex != 1 || res.Level != "error" || res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "hostwarden/web-01/pid_4242" {
		t.Errorf("result 0 = %+v", res)
	}
	if got := run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "etc/ssh/sshd_config.d/50-cloud-init.conf" {
		t.Errorf("file uri = %q", got)
	}
	if len(run.Results[2].Suppressions) != 1 {
		t.Error("suppressed finding should carry a SARIF suppression")
	}
}

func TestLocation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		target, uri string
		line        int
	}{
		{"/etc/sudoers.d/90-deploy:2", "etc/sudoers.d/90-deploy", 2},
		{"/etc/ssh/sshd_config#Ciphers", "etc/ssh/sshd_config", 0},
		{"tcp/0.0.0.0:6379", "hostwarden/h/tcp/0.0.0.0_6379", 0},
		{"user:toor", "hostwarden/h/user_toor", 0},
	}
	for _, tc := range tests {
		loc := location("h", tc.target)
		if loc.PhysicalLocation.ArtifactLocation.URI != tc.uri {
			t.Errorf("%s uri = %q, want %q", tc.target, loc.PhysicalLocation.ArtifactLocation.URI, tc.uri)
		}
		line := 0
		if loc.PhysicalLocation.Region != nil {
			line = loc.PhysicalLocation.Region.StartLine
		}
		if line != tc.line {
			t.Errorf("%s line = %d, want %d", tc.target, line, tc.line)
		}
	}
}

func TestFixScript(t *testing.T) {
	t.Parallel()
	r, _ := sample()
	var buf bytes.Buffer
	if err := FixScript(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"#!/usr/bin/env bash", "set -euo pipefail", "# [CRITICAL] HW-IOC-007", "# kill -9 4242", "# Manual remediation:"} {
		if !strings.Contains(out, want) {
			t.Errorf("script missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dmesg_restrict") {
		t.Error("suppressed findings must not be remediated")
	}
}
