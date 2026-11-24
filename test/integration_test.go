//go:build integration

// Package integration runs hostwarden inside a deliberately misconfigured
// Docker container (test/Dockerfile) and asserts the findings, then scans the
// same container over SSH in fleet mode with strict host key verification.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

const image = "hostwarden-misconfigured:test"

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(file))
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

// startContainer builds the image and runs it with the given authorized key.
func startContainer(t *testing.T, authorizedKey string) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	docker(t, "build", "-t", image, "-f", filepath.Join(repoRoot(t), "test", "Dockerfile"), repoRoot(t))
	name := fmt.Sprintf("hostwarden-it-%d", time.Now().UnixNano())
	docker(t, "run", "-d", "--name", name, "-p", "127.0.0.1::22", "-e", "AUTHORIZED_KEY="+authorizedKey, image)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	deadline := time.Now().Add(60 * time.Second)
	for exec.Command("docker", "exec", name, "test", "-e", "/run/hostwarden-ready").Run() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("container never became ready:\n%s", docker(t, "logs", name))
		}
		time.Sleep(500 * time.Millisecond)
	}
	// Give sshd a moment to bind after the readiness marker.
	time.Sleep(time.Second)
	return name
}

func TestMisconfiguredContainer(t *testing.T) {
	pub, keyPEM := newKey(t)
	name := startContainer(t, pub)

	t.Run("scan", func(t *testing.T) {
		out := docker(t, "exec", name, "/opt/hostwarden/hostwarden", "scan", "--format", "json")
		var rep audit.Report
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("decode: %v\n%s", err, out)
		}
		assertFindings(t, &rep)
	})

	t.Run("fail-on exit code", func(t *testing.T) {
		err := exec.Command("docker", "exec", name, "/opt/hostwarden/hostwarden", "scan", "--fail-on", "critical").Run()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			t.Fatalf("want exit 1, got %v", err)
		}
	})

	t.Run("sarif", func(t *testing.T) {
		out := docker(t, "exec", name, "/opt/hostwarden/hostwarden", "scan", "--format", "sarif")
		var log struct {
			Version string `json:"version"`
			Runs    []struct {
				Results []struct {
					RuleID string `json:"ruleId"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(out), &log); err != nil || log.Version != "2.1.0" || len(log.Runs[0].Results) == 0 {
			t.Fatalf("invalid SARIF (%v): %.300s", err, out)
		}
	})

	t.Run("table sample", func(t *testing.T) {
		out := docker(t, "exec", name, "/opt/hostwarden/hostwarden", "scan", "--color", "never")
		if !strings.Contains(out, "HW-IOC-007") || !strings.Contains(out, "Score 0/100 (F)") {
			t.Fatalf("unexpected table:\n%s", out)
		}
		if p := os.Getenv("HOSTWARDEN_SAMPLE_OUT"); p != "" {
			if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("fix never executes", func(t *testing.T) {
		before := docker(t, "exec", name, "stat", "-c", "%a", "/etc/shadow")
		out := docker(t, "exec", name, "/opt/hostwarden/hostwarden", "fix")
		after := docker(t, "exec", name, "stat", "-c", "%a", "/etc/shadow")
		if !strings.Contains(out, "chmod 640 /etc/shadow") || before != after {
			t.Fatalf("fix must only print: before=%s after=%s", before, after)
		}
	})

	t.Run("fleet over ssh", func(t *testing.T) {
		fleetScan(t, name, keyPEM)
	})
}

func assertFindings(t *testing.T, rep *audit.Report) {
	t.Helper()
	got := map[string]audit.Severity{}
	for _, f := range rep.Findings {
		if f.Severity > got[f.CheckID] {
			got[f.CheckID] = f.Severity
		}
	}
	want := map[string]audit.Severity{
		"HW-SSH-001": audit.High, "HW-SSH-002": audit.High, "HW-SSH-003": audit.Medium, "HW-SSH-004": audit.Low,
		"HW-ACC-001": audit.Critical, "HW-ACC-002": audit.Critical, "HW-ACC-003": audit.High, "HW-ACC-004": audit.Low,
		"HW-NET-001": audit.Critical, "HW-NET-002": audit.Medium,
		"HW-FS-001": audit.Medium, "HW-FS-002": audit.Critical, "HW-FS-003": audit.Low, "HW-FS-004": audit.Critical, "HW-FS-005": audit.Critical,
		"HW-CTR-002": audit.Critical, "HW-CTR-003": audit.Medium,
		"HW-IOC-002": audit.High, "HW-IOC-003": audit.High, "HW-IOC-005": audit.High, "HW-IOC-006": audit.High,
		"HW-IOC-007": audit.Critical, "HW-IOC-008": audit.High, "HW-IOC-010": audit.Medium, "HW-IOC-011": audit.High,
		"HW-KRN-002": audit.Low,
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s: max severity %v, want %v", id, got[id], sev)
		}
	}
	if rep.Score != 0 || len(rep.Errors) != 0 {
		t.Errorf("score=%d errors=%v", rep.Score, rep.Errors)
	}
}

func newKey(t *testing.T) (string, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "hostwarden-it")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " hostwarden-it", pem.EncodeToMemory(block)
}

func goBuild(t *testing.T, dst, goos, goarch string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", dst, "./cmd/hostwarden")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s/%s: %v\n%s", goos, goarch, err, out)
	}
}

func fleetScan(t *testing.T, name string, keyPEM []byte) {
	dir := t.TempDir()
	port := strings.TrimSpace(docker(t, "port", name, "22/tcp"))
	port = port[strings.LastIndex(port, ":")+1:]
	hostKey := strings.Fields(docker(t, "exec", name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"))
	knownHosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(fmt.Sprintf("[127.0.0.1]:%s %s %s\n", port, hostKey[0], hostKey[1])), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(inv, []byte(fmt.Sprintf(`defaults:
  user: root
  identity_file: %s
  known_hosts: %s
hosts:
  - name: misconfigured
    address: 127.0.0.1
    port: %s
`, key, knownHosts, port)), 0o600); err != nil {
		t.Fatal(err)
	}

	arch := "amd64"
	if m := strings.TrimSpace(docker(t, "exec", name, "uname", "-m")); m == "aarch64" {
		arch = "arm64"
	}
	remoteBin := filepath.Join(dir, "hostwarden-linux-"+arch)
	goBuild(t, remoteBin, "linux", arch)
	localBin := filepath.Join(dir, "hostwarden")
	goBuild(t, localBin, runtime.GOOS, runtime.GOARCH)

	cmd := exec.Command(localBin, "fleet", "-i", inv, "--binary", arch+"="+remoteBin, "--format", "json", "--fail-on", "critical")
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("fleet exit = %v (want 1: critical findings)\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	var sum struct {
		Hosts   int `json:"hosts"`
		Failed  int `json:"failed"`
		Results []struct {
			Report *audit.Report `json:"report"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Hosts != 1 || sum.Failed != 0 || sum.Results[0].Report == nil {
		t.Fatalf("fleet summary = %s", stdout.String())
	}
	assertFindings(t, sum.Results[0].Report)
	// The uploaded binary must be cleaned up.
	if out := docker(t, "exec", name, "sh", "-c", "ls -a /root | grep -c hostwarden || true"); strings.TrimSpace(out) != "0" {
		t.Errorf("uploaded binary left behind in /root")
	}

	// A wrong host key must be refused before anything runs.
	impostor, _ := newKey(t)
	f := strings.Fields(impostor)
	if err := os.WriteFile(knownHosts, []byte(fmt.Sprintf("[127.0.0.1]:%s %s %s\n", port, f[0], f[1])), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(localBin, "fleet", "-i", inv, "--binary", arch+"="+remoteBin)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=")
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "key mismatch") {
		t.Errorf("mismatched host key should fail:\n%s", out)
	}
}
