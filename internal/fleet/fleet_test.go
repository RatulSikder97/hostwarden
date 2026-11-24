package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

func TestParseInventory(t *testing.T) {
	t.Parallel()
	yes := true
	tests := []struct {
		name    string
		yaml    string
		wantErr string
		check   func(t *testing.T, inv *Inventory)
	}{
		{name: "defaults applied", yaml: `
defaults:
  user: audit
  port: 2222
  sudo: true
  known_hosts: /etc/hostwarden/known_hosts
  args: ["--exclude", "kernel"]
hosts:
  - name: web-1
    address: 192.0.2.10
  - address: 198.51.100.20
    user: ops
    port: 22
`, check: func(t *testing.T, inv *Inventory) {
			a, b := inv.Hosts[0], inv.Hosts[1]
			if a.User != "audit" || a.Port != 2222 || !a.UseSudo() || a.KnownHosts != "/etc/hostwarden/known_hosts" || len(a.Args) != 2 {
				t.Errorf("host a = %+v", a)
			}
			if b.Name != "198.51.100.20" || b.User != "ops" || b.Port != 22 || *b.Sudo != yes {
				t.Errorf("host b = %+v", b)
			}
		}},
		{name: "default port and known_hosts", yaml: "hosts:\n  - {address: 192.0.2.1, user: u}\n", check: func(t *testing.T, inv *Inventory) {
			h := inv.Hosts[0]
			if h.Port != 22 || !strings.HasSuffix(h.KnownHosts, filepath.Join(".ssh", "known_hosts")) || h.UseSudo() {
				t.Errorf("host = %+v", h)
			}
		}},
		{name: "no hosts", yaml: "defaults: {user: x}\n", wantErr: "no hosts"},
		{name: "missing address", yaml: "hosts:\n  - {name: a, user: u}\n", wantErr: "address is required"},
		{name: "missing user", yaml: "hosts:\n  - {address: 192.0.2.1}\n", wantErr: "user is required"},
		{name: "duplicate", yaml: "defaults: {user: u}\nhosts:\n  - {name: a, address: 192.0.2.1}\n  - {name: a, address: 192.0.2.2}\n", wantErr: "duplicate"},
		{name: "unknown field", yaml: "hosts:\n  - {address: 192.0.2.1, user: u, password: hunter2}\n", wantErr: "password"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inv, err := ParseInventory([]byte(tc.yaml))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, inv)
		})
	}
}

// fakeSSH is an in-process SSH server that emulates the three remote
// commands fleet mode issues.
type fakeSSH struct {
	addr     string
	hostKey  ssh.Signer
	mu       sync.Mutex
	uploaded []byte
	commands []string
}

func startFakeSSH(t *testing.T, clientKey ssh.PublicKey, arch string, rep *audit.Report) *fakeSSH {
	t.Helper()
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(hk)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(clientKey.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("unknown key")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeSSH{addr: ln.Addr().String(), hostKey: signer}
	reportJSON, _ := json.Marshal(rep)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, cfg, arch, reportJSON)
		}
	}()
	return f
}

func (f *fakeSSH) serve(conn net.Conn, cfg *ssh.ServerConfig, arch string, reportJSON []byte) {
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &payload)
				_ = req.Reply(true, nil)
				f.mu.Lock()
				f.commands = append(f.commands, payload.Command)
				f.mu.Unlock()
				status := uint32(0)
				switch {
				case payload.Command == "uname -m":
					_, _ = io.WriteString(ch, arch+"\n")
				case payload.Command == uploadCommand:
					b, _ := io.ReadAll(ch)
					f.mu.Lock()
					f.uploaded = b
					f.mu.Unlock()
					_, _ = io.WriteString(ch, "/home/audit/.hostwarden.Xy12ab\n")
				case strings.Contains(payload.Command, " scan --format json"):
					_, _ = ch.Write(reportJSON)
				default:
					status = 127
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				return
			}
		}()
	}
}

func writeKey(t *testing.T, dir string) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return p, signer.PublicKey()
}

func TestRunAgainstFakeSSH(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath, pub := writeKey(t, dir)
	rep := &audit.Report{Tool: "hostwarden", Host: audit.HostInfo{Hostname: "web-1"}, Score: 65, Grade: "C",
		Findings: []audit.Finding{{CheckID: "HW-SSH-001", Title: "SSH password authentication enabled", Severity: audit.High, Target: "/etc/ssh/sshd_config"}}}
	srv := startFakeSSH(t, pub, "aarch64", rep)
	untrusted := startFakeSSH(t, pub, "x86_64", rep)

	host, port, _ := net.SplitHostPort(srv.addr)
	knownHostsPath := filepath.Join(dir, "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(net.JoinHostPort(host, port))}, srv.hostKey.PublicKey())
	if err := os.WriteFile(knownHostsPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "hostwarden-arm64")
	if err := os.WriteFile(bin, []byte("ELF-arm64"), 0o700); err != nil {
		t.Fatal(err)
	}
	uhost, uport, _ := net.SplitHostPort(untrusted.addr)
	inv, err := ParseInventory(fmt.Appendf(nil, `
defaults: {user: audit, identity_file: %q, known_hosts: %q, sudo: true, args: ["--exclude", "kernel"]}
hosts:
  - {name: trusted, address: %q, port: %s}
  - {name: unknown-key, address: %q, port: %s}
`, keyPath, knownHostsPath, host, port, uhost, uport))
	if err != nil {
		t.Fatal(err)
	}
	results := Run(context.Background(), inv, Options{Binaries: map[string]string{"arm64": bin}, Timeout: 10 * time.Second})

	if results[0].Error != "" || results[0].Report == nil || results[0].Report.Score != 65 {
		t.Fatalf("trusted result = %+v", results[0])
	}
	if results[1].Error == "" || !strings.Contains(results[1].Error, "knownhosts") {
		t.Errorf("unknown host key must be rejected, got %+v", results[1])
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if string(srv.uploaded) != "ELF-arm64" {
		t.Errorf("uploaded %q", srv.uploaded)
	}
	scan := srv.commands[len(srv.commands)-1]
	for _, want := range []string{"sudo -n '/home/audit/.hostwarden.Xy12ab/hostwarden' scan --format json --fail-on none '--exclude' 'kernel'", "rm -rf '/home/audit/.hostwarden.Xy12ab'"} {
		if !strings.Contains(scan, want) {
			t.Errorf("scan command %q missing %q", scan, want)
		}
	}
	if untrusted.commands != nil {
		t.Errorf("no command may run on an unverified host, ran %v", untrusted.commands)
	}

	sum := Summarize(results, time.Now())
	if sum.Failed != 1 || sum.AverageScore != 65 || len(sum.TopChecks) != 1 || !sum.Exceeds(audit.High) || sum.Exceeds(audit.Critical) {
		t.Errorf("summary = %+v", sum)
	}
	var b strings.Builder
	if err := sum.WriteTable(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "trusted") || !strings.Contains(b.String(), "1/1 hosts") {
		t.Errorf("table:\n%s", b.String())
	}
}

func TestMissingBinaryForArch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath, pub := writeKey(t, dir)
	srv := startFakeSSH(t, pub, "x86_64", &audit.Report{})
	host, port, _ := net.SplitHostPort(srv.addr)
	kh := filepath.Join(dir, "known_hosts")
	_ = os.WriteFile(kh, []byte(knownhosts.Line([]string{knownhosts.Normalize(srv.addr)}, srv.hostKey.PublicKey())+"\n"), 0o600)
	inv, err := ParseInventory(fmt.Appendf(nil, "hosts:\n  - {address: %q, port: %s, user: a, identity_file: %q, known_hosts: %q}\n", host, port, keyPath, kh))
	if err != nil {
		t.Fatal(err)
	}
	res := Run(context.Background(), inv, Options{Binaries: map[string]string{"arm64": "/nonexistent"}})
	if !strings.Contains(res[0].Error, "no hostwarden binary for remote arch amd64") {
		t.Errorf("err = %q", res[0].Error)
	}
}

func TestExampleInventory(t *testing.T) {
	t.Parallel()
	inv, err := LoadInventory(filepath.Join("..", "..", "examples", "inventory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Hosts) != 3 || inv.Hosts[2].User != "ops" || !inv.Hosts[0].UseSudo() {
		t.Errorf("hosts = %+v", inv.Hosts)
	}
}
