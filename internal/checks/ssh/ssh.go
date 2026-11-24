// Package ssh audits the OpenSSH server configuration and authorized_keys hygiene.
package ssh

import (
	"context"
	"crypto/rsa"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	xssh "golang.org/x/crypto/ssh"

	"github.com/RatulSikder97/hostwarden/internal/audit"
	"github.com/RatulSikder97/hostwarden/internal/host"
)

// Checks returns the SSH checks.
func Checks() []audit.Check {
	return []audit.Check{
		{
			ID:       "HW-SSH-001",
			Title:    "SSH password authentication enabled",
			Category: audit.CategorySSH,
			Severity: audit.High,
			Rationale: "Password logins expose the host to credential stuffing and brute force; internet-facing " +
				"sshd receives thousands of guessing attempts per day. CIS 5.2.x recommends key-only authentication.",
			Remediation: "Set `PasswordAuthentication no` (and `KbdInteractiveAuthentication no`) in /etc/ssh/sshd_config, then reload sshd.",
			Fix: `sed -i -E 's/^#?\s*PasswordAuthentication\s+.*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
sshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd`,
			Run: settingCheck("passwordauthentication", func(v string) bool { return v != "no" }),
		},
		{
			ID:          "HW-SSH-002",
			Title:       "SSH root login permitted",
			Category:    audit.CategorySSH,
			Severity:    audit.High,
			Rationale:   "Direct root login removes accountability and gives an attacker full control from a single guessed credential.",
			Remediation: "Set `PermitRootLogin no` (or `prohibit-password` if key-based root automation is required).",
			Fix: `sed -i -E 's/^#?\s*PermitRootLogin\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config
sshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd`,
			Run: settingCheck("permitrootlogin", func(v string) bool { return v == "yes" }),
		},
		{
			ID:          "HW-SSH-003",
			Title:       "Weak SSH ciphers, MACs or key exchange algorithms",
			Category:    audit.CategorySSH,
			Severity:    audit.Medium,
			Rationale:   "CBC-mode ciphers, SHA-1/MD5 MACs and SHA-1 Diffie-Hellman groups are vulnerable to known attacks (e.g. Terrapin-adjacent downgrades, Logjam).",
			Remediation: "Remove legacy algorithms from Ciphers, MACs and KexAlgorithms; rely on OpenSSH defaults or a modern allow-list.",
			Run:         runWeakAlgorithms,
		},
		{
			ID:          "HW-SSH-004",
			Title:       "SSH MaxAuthTries too high",
			Category:    audit.CategorySSH,
			Severity:    audit.Low,
			Rationale:   "A high MaxAuthTries lets attackers try many keys or passwords per connection. CIS recommends 4 or fewer.",
			Remediation: "Set `MaxAuthTries 3` in /etc/ssh/sshd_config.",
			Fix:         `sed -i -E 's/^#?\s*MaxAuthTries\s+.*/MaxAuthTries 3/' /etc/ssh/sshd_config`,
			Run: settingCheck("maxauthtries", func(v string) bool {
				n, err := strconv.Atoi(v)
				return err != nil || n > 4
			}),
		},
		{
			ID:          "HW-SSH-005",
			Title:       "SSH permits empty passwords",
			Category:    audit.CategorySSH,
			Severity:    audit.Critical,
			Rationale:   "Accounts without a password become reachable over the network with no credential at all.",
			Remediation: "Set `PermitEmptyPasswords no` in /etc/ssh/sshd_config.",
			Fix:         `sed -i -E 's/^#?\s*PermitEmptyPasswords\s+.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config`,
			Run:         settingCheck("permitemptypasswords", func(v string) bool { return v == "yes" }),
		},
		{
			ID:          "HW-SSH-006",
			Title:       "Weak or loosely protected authorized_keys",
			Category:    audit.CategorySSH,
			Severity:    audit.Medium,
			Rationale:   "DSA and short RSA keys are factorable; group/world-writable authorized_keys files let other local users add their own keys.",
			Remediation: "Replace DSA and RSA<2048 keys with ed25519, and `chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh`.",
			Run:         runAuthorizedKeys,
		},
	}
}

// keyAlgoDSA is matched lexically: x/crypto no longer parses DSA keys.
const keyAlgoDSA = "ssh-dss"

// settingCheck builds a Run func that flags an sshd keyword when bad(value).
func settingCheck(keyword string, bad func(string) bool) func(context.Context, *host.Host) ([]audit.Finding, error) {
	return func(_ context.Context, h *host.Host) ([]audit.Finding, error) {
		cfg, err := loadSSHDConfig(h)
		if err != nil {
			if host.IsNotExist(err) {
				return nil, audit.Skip("no %s", sshdConfigPath)
			}
			return nil, err
		}
		s := cfg.get(keyword)
		if !bad(strings.ToLower(s.Value)) {
			return nil, nil
		}
		target := sshdConfigPath
		if s.Source != "default" {
			target = strings.SplitN(s.Source, ":", 2)[0]
		}
		return []audit.Finding{{
			Target:   target,
			Message:  fmt.Sprintf("effective %s is %q", canonical(keyword), s.Value),
			Evidence: []string{fmt.Sprintf("%s %s (%s)", canonical(keyword), s.Value, s.Source)},
		}}, nil
	}
}

var canonicalNames = map[string]string{
	"passwordauthentication": "PasswordAuthentication",
	"permitrootlogin":        "PermitRootLogin",
	"maxauthtries":           "MaxAuthTries",
	"permitemptypasswords":   "PermitEmptyPasswords",
	"ciphers":                "Ciphers",
	"macs":                   "MACs",
	"kexalgorithms":          "KexAlgorithms",
}

func canonical(k string) string {
	if c, ok := canonicalNames[k]; ok {
		return c
	}
	return k
}

var weakAlgorithms = map[string][]string{
	"ciphers": {
		"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc",
		"arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se",
	},
	"macs": {
		"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com",
		"hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
		"umac-64-etm@openssh.com", "hmac-ripemd160",
	},
	"kexalgorithms": {
		"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1", "gss-group1-sha1-", "gss-gex-sha1-",
	},
}

func runWeakAlgorithms(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	cfg, err := loadSSHDConfig(h)
	if err != nil {
		if host.IsNotExist(err) {
			return nil, audit.Skip("no %s", sshdConfigPath)
		}
		return nil, err
	}
	var out []audit.Finding
	for _, kw := range []string{"ciphers", "kexalgorithms", "macs"} {
		s, ok := cfg.explicit(kw)
		if !ok {
			continue // OpenSSH defaults contain no algorithms on these lists.
		}
		value := s.Value
		// "-list" removes from the defaults; it can never add a weak algorithm.
		if strings.HasPrefix(value, "-") {
			continue
		}
		value = strings.TrimLeft(value, "+^")
		var weak []string
		for alg := range strings.SplitSeq(value, ",") {
			alg = strings.ToLower(strings.TrimSpace(alg))
			if slices.ContainsFunc(weakAlgorithms[kw], func(w string) bool {
				return alg == w || (strings.HasSuffix(w, "-") && strings.HasPrefix(alg, w))
			}) {
				weak = append(weak, alg)
			}
		}
		if len(weak) == 0 {
			continue
		}
		file := strings.SplitN(s.Source, ":", 2)[0]
		out = append(out, audit.Finding{
			Target:   file + "#" + canonical(kw),
			Message:  fmt.Sprintf("%s enables weak algorithms: %s", canonical(kw), strings.Join(weak, ", ")),
			Evidence: []string{fmt.Sprintf("%s %s (%s)", canonical(kw), s.Value, s.Source)},
			Fix: fmt.Sprintf("# Remove %s from the %s line in %s, then:\nsshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd",
				strings.Join(weak, ","), canonical(kw), file),
		})
	}
	return out, nil
}

func runAuthorizedKeys(_ context.Context, h *host.Host) ([]audit.Finding, error) {
	var out []audit.Finding
	for _, home := range h.HomeDirs() {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := path.Join(home, ".ssh", name)
			fi, err := h.Lstat(p)
			if err != nil {
				continue
			}
			if fi.Mode().Perm()&0o022 != 0 {
				out = append(out, audit.Finding{
					Target:   p,
					Severity: audit.High,
					Message:  fmt.Sprintf("%s is writable by group or others (mode %04o)", p, fi.Mode().Perm()),
					Fix:      fmt.Sprintf("chmod 600 %s && chmod 700 %s", p, path.Dir(p)),
				})
			}
			lines, err := h.Lines(p)
			if err != nil {
				continue
			}
			for _, l := range lines {
				text := strings.TrimSpace(l.Text)
				if text == "" || strings.HasPrefix(text, "#") {
					continue
				}
				pk, comment, _, _, err := xssh.ParseAuthorizedKey([]byte(text))
				if err != nil {
					// x/crypto no longer parses ssh-dss; detect it lexically.
					if slices.Contains(strings.Fields(text), keyAlgoDSA) {
						out = append(out, audit.Finding{
							Target:  fmt.Sprintf("%s:%d", p, l.N),
							Message: "ssh-dss key: DSA keys are limited to 1024 bits and disabled by modern OpenSSH",
							Fix:     fmt.Sprintf("# Replace this key with an ed25519 key, then delete line %d of %s", l.N, p),
						})
					}
					continue
				}
				if reason := weakKey(pk); reason != "" {
					target := fmt.Sprintf("%s:%d", p, l.N)
					out = append(out, audit.Finding{
						Target:   target,
						Message:  fmt.Sprintf("%s key %q: %s", pk.Type(), comment, reason),
						Evidence: []string{"fingerprint " + xssh.FingerprintSHA256(pk)},
						Fix:      fmt.Sprintf("# Replace this key with an ed25519 key, then delete line %d of %s", l.N, p),
					})
				}
			}
		}
	}
	return out, nil
}

func weakKey(pk xssh.PublicKey) string {
	if pk.Type() != xssh.KeyAlgoRSA {
		return ""
	}
	cpk, ok := pk.(xssh.CryptoPublicKey)
	if !ok {
		return ""
	}
	if rk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < 2048 {
		return fmt.Sprintf("RSA modulus is %d bits (< 2048)", rk.N.BitLen())
	}
	return ""
}
