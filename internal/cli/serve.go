package cli

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"time"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/exporter"
)

func runServe(ctx context.Context, args []string, streams IO) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(streams.Stderr)
	var o scanOptions
	o.register(fs)
	metrics := fs.Bool("metrics", false, "serve Prometheus metrics on /metrics (required)")
	listen := fs.String("listen", "127.0.0.1:9727", "listen address")
	interval := fs.Duration("interval", 10*time.Minute, "rescan interval")
	if ok, code := parseFlags(fs, args); !ok {
		return code
	}
	if !*metrics {
		return errorf(streams.Stderr, "serve: only the Prometheus exporter is available; pass --metrics")
	}
	if *interval < time.Minute {
		return errorf(streams.Stderr, "serve: --interval must be at least 1m")
	}
	log := slog.New(slog.NewTextHandler(streams.Stderr, nil))
	exp := exporter.New(func(ctx context.Context) (*audit.Report, error) {
		rep, _, err := o.scan(ctx)
		return rep, err
	}, *interval, version(), log)

	srv := &http.Server{Addr: *listen, Handler: exp.Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go exp.Run(ctx)

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("serving metrics", "addr", *listen, "interval", interval.String())
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return errorf(streams.Stderr, "serve: %v", err)
		}
	case <-ctx.Done():
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return errorf(streams.Stderr, "shutdown: %v", err)
		}
	}
	return ExitOK
}
