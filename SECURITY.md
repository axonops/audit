# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| v0.x    | :white_check_mark: |

Only the latest minor release receives security patches. This project
is pre-release; the API and security posture are actively evolving.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use [GitHub Security Advisories](https://github.com/axonops/audit/security/advisories/new)
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

If you believe you have found a flaw in the library's own defences
— not in how a consumer uses it — we want to hear about it. Examples
of what we consider in scope:

- A way to bypass the webhook output's SSRF protection so that
  requests reach private networks despite the guard being enabled
- A flaw that forces a TLS connection to downgrade below the
  configured minimum version
- The library itself leaking credentials (e.g., webhook auth headers
  appearing in error messages or log output)
- A way to cause the library to consume unbounded memory or CPU
  through crafted taxonomy definitions or configuration, independent
  of the audit data a consumer passes in

### Out of scope

The following are normal usage, bugs, or consumer responsibility and
should be reported as regular GitHub issues, not security reports:

- Consumers passing arbitrary data in audit fields — the library
  records what it is given; it is not responsible for sanitising
  application-level content
- Bugs in formatting, field ordering, or output structure
- Performance issues
- Consumer misconfiguration (e.g., choosing to disable TLS validation
  or setting `AllowInsecureHTTP`)
- Issues in test infrastructure or CI/CD pipelines
- Feature requests

## Software Bill of Materials (SBOM)

Every release includes SBOMs in two formats, published as assets in
the [GitHub Release](https://github.com/axonops/audit/releases):

| Format | Filename | Use Case |
|--------|----------|----------|
| **CycloneDX** | `go-audit_<version>_sbom.cdx.json` | Vulnerability scanners (Trivy, Grype, Dependency-Track) |
| **SPDX** | `go-audit_<version>_sbom.spdx.json` | License compliance tools, regulatory reporting |

Both SBOMs list all direct and transitive dependencies across every
module in the repository, including versions and license identifiers.

### Using the SBOM

Scan for vulnerabilities:

```bash
# Download the SBOM from the GitHub release, then:
trivy sbom go-audit_v0.1.0_sbom.cdx.json
```

Generate a local SBOM from source (requires [syft](https://github.com/anchore/syft)):

```bash
make sbom            # generates CycloneDX + SPDX in sbom/
make sbom-validate   # validates JSON structure
```
