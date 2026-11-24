package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/RatulSikder97/hostwarden/internal/audit"
)

// Options configures a fleet run.
type Options struct {
	// Binaries maps GOARCH (amd64, arm64) to a local linux binary to upload.
	Binaries    map[string]string
	Concurrency int
	// Timeout bounds the whole per-host interaction.
	Timeout time.Duration
	// Agent, if non-nil, supplies signers (normally from SSH_AUTH_SOCK).
	Agent agent.Agent
}

// Result is the outcome for one host.
type Result struct {
	Name    string        `json:"name"`
	Address string        `json:"address"`
	Report  *audit.Report `json:"report,omitempty"`
	Error   string        `json:"error,omitempty"`
}

// Run scans every host in inv with bounded concurrency. Results keep
// inventory order.
func Run(ctx context.Context, inv *Inventory, opts Options) []Result {
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 8
	}
	results := make([]Result, len(inv.Hosts))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, h := range inv.Hosts {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			res := Result{Name: h.Name, Address: net.JoinHostPort(h.Address, strconv.Itoa(h.Port))}
			rep, err := scanHost(ctx, h, opts)
			if err != nil {
				res.Error = err.Error()
			}
			res.Report = rep
			results[i] = res
		})
	}
	wg.Wait()
	return results
}

func scanHost(ctx context.Context, h HostSpec, opts Options) (*audit.Report, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := dial(ctx, h, opts.Agent)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	// Closing the client unblocks any session still waiting when ctx expires.
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()

	arch, err := remoteArch(client)
	if err != nil {
		return nil, err
	}
	binPath, ok := opts.Binaries[arch]
	if !ok {
		return nil, fmt.Errorf("no hostwarden binary for remote arch %s (pass --binary %s=PATH)", arch, arch)
	}
	bin, err := os.ReadFile(binPath)
	if err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}
	dir, err := upload(client, bin)
	if err != nil {
		return nil, err
	}
	out, runErr := run(client, scanCommand(dir, h))
	if runErr != nil {
		// The scan command removes the directory itself; make sure it is gone
		// even if the session failed before that ran.
		_, _ = run(client, "rm -rf "+audit.ShellQuote(dir))
		if ctx.Err() != nil {
			return nil, fmt.Errorf("scan timed out: %w", ctx.Err())
		}
		return nil, runErr
	}
	var rep audit.Report
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, fmt.Errorf("decode remote report: %w", err)
	}
	return &rep, nil
}

func dial(ctx context.Context, h HostSpec, ag agent.Agent) (*ssh.Client, error) {
	hostKeys, err := knownhosts.New(h.KnownHosts)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", h.KnownHosts, err)
	}
	auth, err := authMethods(h, ag)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(h.Address, strconv.Itoa(h.Port))
	cfg := &ssh.ClientConfig{
		User:            h.User,
		Auth:            auth,
		HostKeyCallback: hostKeys,
		Timeout:         20 * time.Second,
	}
	client, err := dialConfig(ctx, addr, cfg)
	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
		// The host is known, but under a different key type than the server
		// offered first. Retry restricted to the recorded algorithms; a
		// genuine key mismatch still fails.
		for _, k := range keyErr.Want {
			cfg.HostKeyAlgorithms = append(cfg.HostKeyAlgorithms, hostKeyAlgorithms(k.Key.Type())...)
		}
		client, err = dialConfig(ctx, addr, cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("ssh %s@%s: %w", h.User, addr, err)
	}
	return client, nil
}

func hostKeyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

func dialConfig(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func authMethods(h HostSpec, ag agent.Agent) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if h.IdentityFile != "" {
		pem, err := os.ReadFile(h.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("read identity file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			var pp *ssh.PassphraseMissingError
			if errors.As(err, &pp) {
				return nil, fmt.Errorf("identity file %s is passphrase-protected; load it into ssh-agent instead", h.IdentityFile)
			}
			return nil, fmt.Errorf("parse identity file %s: %w", h.IdentityFile, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if ag != nil {
		methods = append(methods, ssh.PublicKeysCallback(ag.Signers))
	}
	if len(methods) == 0 {
		return nil, errors.New("no SSH credentials: set identity_file or run an ssh-agent")
	}
	return methods, nil
}

// AgentFromEnv connects to SSH_AUTH_SOCK if set.
func AgentFromEnv(ctx context.Context) (agent.Agent, func(), error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, func() {}, nil
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, func() {}, fmt.Errorf("connect to ssh-agent: %w", err)
	}
	return agent.NewClient(conn), func() { _ = conn.Close() }, nil
}

func run(client *ssh.Client, cmd string) ([]byte, error) {
	return runInput(client, cmd, nil)
}

func runInput(client *ssh.Client, cmd string, stdin []byte) ([]byte, error) {
	s, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}
	defer s.Close()
	var stdout, stderr bytes.Buffer
	s.Stdout, s.Stderr = &stdout, &stderr
	if stdin != nil {
		s.Stdin = bytes.NewReader(stdin)
	}
	if err := s.Run(cmd); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return nil, fmt.Errorf("remote command failed: %w: %s", err, msg)
	}
	return stdout.Bytes(), nil
}

func remoteArch(client *ssh.Client) (string, error) {
	out, err := run(client, "uname -m")
	if err != nil {
		return "", err
	}
	switch m := strings.TrimSpace(string(out)); m {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported remote architecture %q", m)
	}
}

// uploadCommand stores stdin as an executable in a fresh 0700 directory under
// $HOME (not /tmp, which hardened hosts mount noexec) and prints the path.
const uploadCommand = `umask 077 && d=$(mktemp -d "${HOME:-/tmp}/.hostwarden.XXXXXX") && cat > "$d/hostwarden" && chmod 700 "$d/hostwarden" && printf '%s\n' "$d"`

func upload(client *ssh.Client, bin []byte) (string, error) {
	out, err := runInput(client, uploadCommand, bin)
	if err != nil {
		return "", fmt.Errorf("upload binary: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" || !strings.Contains(dir, ".hostwarden.") {
		return "", fmt.Errorf("upload binary: unexpected remote path %q", dir)
	}
	return dir, nil
}

func scanCommand(dir string, h HostSpec) string {
	args := []string{audit.ShellQuote(dir + "/hostwarden"), "scan", "--format", "json", "--fail-on", "none"}
	for _, a := range h.Args {
		args = append(args, audit.ShellQuote(a))
	}
	cmd := strings.Join(args, " ")
	if h.UseSudo() {
		cmd = "sudo -n " + cmd
	}
	return fmt.Sprintf("%s; rc=$?; rm -rf %s; exit $rc", cmd, audit.ShellQuote(dir))
}
