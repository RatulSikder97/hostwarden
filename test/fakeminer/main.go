// Command fakeminer imitates a crypto-miner for hostwarden's integration test
// without mining anything: it accepts miner-style flags, opens a "stratum"
// connection to a listener it hosts itself on 127.0.0.1:3333, and idles.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.String("o", "", "pool URL (ignored)")
	flag.Int("donate-level", 1, "ignored")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:3333")
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:3333")
	if err != nil {
		return err
	}
	defer conn.Close()
	<-ctx.Done()
	return nil
}
