// Package compromise looks for persistence mechanisms and runtime indicators
// left behind by real-world intrusions, with a focus on crypto-miner droppers
// delivered through exposed services and container RCEs.
package compromise

import "github.com/RatulSikder97/hostwarden/internal/audit"

// Checks returns the compromise-indicator checks.
func Checks() []audit.Check {
	return []audit.Check{
		{
			ID:          "HW-IOC-001",
			Title:       "Global library preload configured",
			Category:    audit.CategoryCompromise,
			Severity:    audit.Critical,
			Rationale:   "/etc/ld.so.preload is the standard hiding place for userland rootkits (libprocesshider, Kinsing's loader) that conceal miner processes from ps and top.",
			Remediation: "Treat the host as compromised: capture the library for analysis, remove the preload entry, and rebuild from a known-good image.",
			Run:         runPreload,
		},
		{
			ID:          "HW-IOC-002",
			Title:       "Suspicious cron job",
			Category:    audit.CategoryCompromise,
			Severity:    audit.High,
			Rationale:   "Miner droppers re-infect via cron (`curl ... | sh` every few minutes) so that killing the process is not enough.",
			Remediation: "Remove the entry, then hunt for the downloaded payload and the original entry point.",
			Run:         runCron,
		},
		{
			ID:          "HW-IOC-003",
			Title:       "Suspicious systemd unit",
			Category:    audit.CategoryCompromise,
			Severity:    audit.High,
			Rationale:   "Attackers install services with innocuous names (\"system-update.service\") whose ExecStart points into /tmp or pulls a remote script.",
			Remediation: "Stop and disable the unit, preserve it as evidence, remove it and run `systemctl daemon-reload`.",
			Run:         runSystemd,
		},
		{
			ID:          "HW-IOC-004",
			Title:       "Suspicious command in rc.local, init script or shell profile",
			Category:    audit.CategoryCompromise,
			Severity:    audit.High,
			Rationale:   "rc.local, /etc/profile.d and ~/.bashrc run on boot or login and are a low-effort persistence point.",
			Remediation: "Remove the injected line and determine how the file was modified.",
			Run:         runInitScripts,
		},
		{
			ID:          "HW-IOC-005",
			Title:       "Process running from a deleted binary",
			Category:    audit.CategoryCompromise,
			Severity:    audit.High,
			Rationale:   "Malware commonly deletes its executable after launch, or runs from memfd, to frustrate forensics. Legitimate cases are daemons awaiting restart after an upgrade.",
			Remediation: "Recover the binary from /proc/PID/exe for analysis before killing the process.",
			Run:         runDeletedExe,
		},
		{
			ID:          "HW-IOC-006",
			Title:       "Process executing from a world-writable directory",
			Category:    audit.CategoryCompromise,
			Severity:    audit.High,
			Rationale:   "Legitimate software is not executed from /tmp, /var/tmp or /dev/shm; droppers are.",
			Remediation: "Capture the binary and its network connections, then kill the process and mount these paths noexec.",
			Run:         runStagingExe,
		},
		{
			ID:       "HW-IOC-007",
			Title:    "Crypto-miner process",
			Category: audit.CategoryCompromise,
			Severity: audit.Critical,
			Rationale: "Known miner names (xmrig, kdevtmpfsi, kinsing), stratum URLs, miner-specific arguments, pool-port connections " +
				"and sustained CPU from hidden binaries are the signature of cryptojacking.",
			Remediation: "Isolate the host, capture the process, find the initial access vector (exposed service, leaked key) and rebuild.",
			Run:         runMiners,
		},
		{
			ID:          "HW-IOC-008",
			Title:       "Outbound connection to a mining-pool port",
			Category:    audit.CategoryCompromise,
			Severity:    audit.High,
			Rationale:   "Stratum pools listen on a small set of well-known ports (3333, 4444, 5555, 7777, 14444, ...); servers rarely need egress to them.",
			Remediation: "Block the destination, identify the owning process, and restrict egress to required destinations.",
			Run:         runPoolConnections,
		},
		{
			ID:          "HW-IOC-009",
			Title:       "Recently modified system binaries",
			Category:    audit.CategoryCompromise,
			Severity:    audit.Medium,
			Rationale:   "Rootkits replace ps, netstat, ss and top. Binaries changed outside a package upgrade window deserve scrutiny.",
			Remediation: "Correlate with package manager logs and verify with `dpkg --verify` or `rpm -Va`.",
			Run:         runRecentBinaries,
		},
		{
			ID:          "HW-IOC-010",
			Title:       "SSH authorized_keys modified recently",
			Category:    audit.CategoryCompromise,
			Severity:    audit.Medium,
			Rationale:   "Adding an SSH key is the most common post-exploitation persistence step after a credential or RCE compromise.",
			Remediation: "Review every key against your inventory; remove unknown keys and rotate access.",
			Run:         runRecentKeys,
		},
		{
			ID:          "HW-IOC-011",
			Title:       "System binary differs from package checksum",
			Category:    audit.CategoryCompromise,
			Severity:    audit.High,
			Rationale:   "A binary that no longer matches the md5sum its package installed has been replaced or patched, a hallmark of trojaned coreutils.",
			Remediation: "Compare against a known-good copy and reinstall the package; treat the host as compromised if unexplained.",
			Run:         runPackageIntegrity,
		},
	}
}
