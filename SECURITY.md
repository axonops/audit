# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| v0.x    | :white_check_mark: |

Only the latest minor release receives security patches. This project
is pre-release; the API and security posture are actively evolving.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use [GitHub Security Advisories](https://github.com/axonops/go-audit/security/advisories/new)
to report vulnerabilities. This provides a private channel for coordinated disclosure.

### What to include

- Description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Affected versions and components (core, file, syslog, webhook, audit-gen)
- Any suggested mitigation or fix

### Response timeline

- **Acknowledgement**: within 48 hours of report
- **Triage**: within 7 days — we will confirm whether the report is a
  valid vulnerability, request additional information, or close as
  not-a-vulnerability
- **Fix timeline**: depends on severity — critical issues are prioritised
  for the next patch release

These timelines are best-effort commitments for a pre-release project
with a small maintainer team.

## Disclosure Policy

We follow coordinated disclosure with a 90-day window:

1. Reporter submits via GitHub Security Advisories
2. We acknowledge and triage within the timelines above
3. We develop and test a fix
4. We publish a patched release and a GitHub Security Advisory
5. Reporter may publish their findings after the advisory is published,
   or after 90 days from the initial report — whichever comes first

## Scope

The following are considered security vulnerabilities:

- **SSRF bypass** in the webhook output's SSRF protection
- **TLS downgrade** or bypass of TLS policy enforcement
- **Credential leakage** in error messages, logs, or generated output
- **Injection** — template injection in audit-gen, header injection in
  webhook output, log injection in syslog output
- **Denial of service** via crafted taxonomy input or audit fields that
  causes unbounded resource consumption
- **Authentication bypass** in mTLS verification

The following are **not** security vulnerabilities:

- Bugs in formatting, field ordering, or output structure
- Performance issues
- Consumer misconfiguration (e.g., disabling TLS validation)
- Issues in test infrastructure or CI/CD pipelines
- Feature requests
