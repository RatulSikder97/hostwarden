// Package exporter exposes periodic scan results as Prometheus metrics.
package exporter

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

// Scanner produces a fresh report.
type Scanner func(ctx context.Context) (*audit.Report, error)

// Exporter rescans on an interval and publishes the latest results.
type Exporter struct {
	scan     Scanner
	interval time.Duration
	log      *slog.Logger
	reg      *prometheus.Registry
	ready    atomic.Bool

	score       prometheus.Gauge
	bySeverity  *prometheus.GaugeVec
	byCheck     *prometheus.GaugeVec
	suppressed  prometheus.Gauge
	checkErrors prometheus.Gauge
	lastScan    prometheus.Gauge
	duration    prometheus.Gauge
	scans       *prometheus.CounterVec
}

// New builds an Exporter. Metrics are registered on a private registry.
func New(scan Scanner, interval time.Duration, version string, log *slog.Logger) *Exporter {
	e := &Exporter{
		scan:     scan,
		interval: interval,
		log:      log,
		reg:      prometheus.NewRegistry(),
		score: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hostwarden_score", Help: "Host security score from 0 (worst) to 100.",
		}),
		bySeverity: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hostwarden_findings", Help: "Active findings by severity.",
		}, []string{"severity"}),
		byCheck: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hostwarden_check_findings", Help: "Active findings per check.",
		}, []string{"check_id", "severity", "category"}),
		suppressed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hostwarden_findings_suppressed", Help: "Findings suppressed by the baseline.",
		}),
		checkErrors: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hostwarden_check_errors", Help: "Checks that failed with an error in the last scan.",
		}),
		lastScan: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hostwarden_last_scan_timestamp_seconds", Help: "Unix time the last scan completed.",
		}),
		duration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hostwarden_scan_duration_seconds", Help: "Duration of the last scan.",
		}),
		scans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hostwarden_scans_total", Help: "Scans attempted, by result.",
		}, []string{"result"}),
	}
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "hostwarden_build_info", Help: "Build information.", ConstLabels: prometheus.Labels{"version": version},
	})
	info.Set(1)
	e.reg.MustRegister(e.score, e.bySeverity, e.byCheck, e.suppressed, e.checkErrors, e.lastScan, e.duration, e.scans, info)
	return e
}

// ScanOnce runs one scan and updates the metrics.
func (e *Exporter) ScanOnce(ctx context.Context) error {
	start := time.Now()
	rep, err := e.scan(ctx)
	if err != nil {
		e.scans.WithLabelValues("error").Inc()
		return err
	}
	e.scans.WithLabelValues("success").Inc()
	e.score.Set(float64(rep.Score))
	e.bySeverity.Reset()
	for sev, n := range rep.Summary {
		e.bySeverity.WithLabelValues(sev).Set(float64(n))
	}
	e.byCheck.Reset()
	for _, f := range rep.Active() {
		e.byCheck.WithLabelValues(f.CheckID, f.Severity.String(), string(f.Category)).Inc()
	}
	e.suppressed.Set(float64(rep.Suppressed))
	e.checkErrors.Set(float64(len(rep.Errors)))
	e.lastScan.Set(float64(time.Now().Unix()))
	e.duration.Set(time.Since(start).Seconds())
	e.ready.Store(true)
	return nil
}

// Run scans immediately and then every interval until ctx is cancelled.
func (e *Exporter) Run(ctx context.Context) {
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		if err := e.ScanOnce(ctx); err != nil && ctx.Err() == nil {
			e.log.Error("scan failed", "err", err)
		} else if err == nil {
			e.log.Info("scan complete")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Handler serves /metrics and /healthz (503 until the first scan finishes).
func (e *Exporter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(e.reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !e.ready.Load() {
			http.Error(w, "first scan pending", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}
