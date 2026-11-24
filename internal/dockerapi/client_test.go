package dockerapi

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainersOverUnixSocket(t *testing.T) {
	t.Parallel()
	// macOS caps unix socket paths at 104 bytes; t.TempDir() can exceed it.
	dir, err := os.MkdirTemp("", "hw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	var methods []string
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		_, _ = w.Write([]byte(`[{"Id":"0123456789abcdef0123"}]`))
	})
	mux.HandleFunc("/containers/0123456789abcdef0123/json", func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		_, _ = w.Write([]byte(`{"Id":"0123456789abcdef0123","Name":"/miner","Config":{"User":"","Image":"alpine"},
			"HostConfig":{"Privileged":true,"NetworkMode":"host","PidMode":"","CapAdd":["SYS_ADMIN"]},
			"Mounts":[{"Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true}]}`))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	cts, err := Cached(New(sock)).Containers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cts) != 1 {
		t.Fatalf("containers = %+v", cts)
	}
	c := cts[0]
	if c.ID != "0123456789ab" || c.Name != "miner" || !c.Privileged || c.NetworkMode != "host" || len(c.Mounts) != 1 || !c.Mounts[0].ReadWrite {
		t.Errorf("container = %+v", c)
	}
	if strings.Join(methods, ",") != "GET,GET" {
		t.Errorf("client must be read-only, saw %v", methods)
	}
}

func TestErrorStatus(t *testing.T) {
	t.Parallel()
	c := NewWithHTTP(&http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Body: http.NoBody}, nil
	})}, "http://docker")
	if _, err := c.Containers(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("err = %v", err)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
