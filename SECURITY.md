# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/RatulSikder97/hostwarden/security/advisories/new).
Do not open a public issue for security problems.

Include the hostwarden version (`hostwarden version`), the command you ran, and
a minimal reproduction. You can expect an acknowledgement within 3 working days
and a fix or mitigation plan within 14 days for confirmed issues.

## Scope

In scope:

- Anything that makes hostwarden **modify** the audited host (it is designed to
  be strictly read-only; `fix` only prints scripts).
- Fleet mode weaknesses: host-key verification bypass, command injection through
  inventory values, leftover binaries or credentials on remote hosts.
- Crashes or resource exhaustion triggered by attacker-controlled files on the
  audited host (a compromised host is part of the threat model).
- The Prometheus exporter exposing more than aggregate metrics.

Out of scope:

- Detection gaps (a technique hostwarden does not detect). Please open a normal
  issue or pull request with a new check instead.
- Findings in the deliberately vulnerable integration-test image under `test/`.

## Supported versions

Only the latest release receives fixes.
