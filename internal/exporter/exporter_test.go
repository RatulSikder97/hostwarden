package exporter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

func TestExporter(t *testing.T) {
	t.Parallel()
	rep := &audit.Report{Findings: []audit.Finding{
		{CheckID: "HW-IOC-007", Severity: audit.Critical, Category: audit.CategoryCompromise},
		{CheckID: "HW-KRN-001", Severity: audit.Low, Category: audit.CategoryKernel},
		{CheckID: "HW-KRN-001", Severity: audit.Low, Category: audit.CategoryKernel},
		{CheckID: "HW-ACC-004", Severity: audit.Low, Suppressed: true},
	}}
	rep.Rescore()
	fail := false
	e := New(func(context.Context) (*audit.Report, error) {
		if fail {
			return nil, errors.New("boom")
		}
		return rep, nil
	}, time.Hour, "1.2.3", slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(e.Handler())
	defer srv.Close()

	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/healthz"); code != http.StatusServiceUnavailable {
		t.Errorf("healthz before scan = %d", code)
	}
	if err := e.ScanOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := e.ScanOnce(context.Background()); err == nil {
		t.Fatal("expected scan error")
	}
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Errorf("healthz after scan = %d", code)
	}
	_, body := get("/metrics")
	for _, want := range []string{
		"hostwarden_score 73",
		`hostwarden_findings{severity="critical"} 1`,
		`hostwarden_check_findings{category="kernel",check_id="HW-KRN-001",severity="low"} 2`,
		"hostwarden_findings_suppressed 1",
		`hostwarden_scans_total{result="error"} 1`,
		`hostwarden_scans_total{result="success"} 1`,
		`hostwarden_build_info{version="1.2.3"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if strings.Contains(body, "HW-ACC-004") {
		t.Error("suppressed check exported as active")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	scans := make(chan struct{}, 1)
	e := New(func(context.Context) (*audit.Report, error) {
		select {
		case scans <- struct{}{}:
		default:
		}
		return &audit.Report{}, nil
	}, time.Hour, "t", slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	<-scans
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
