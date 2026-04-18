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

## Credential Safety in Log Output

The library never writes credentials to the diagnostic logger under
normal operation. For defence in depth, the output modules also guard
the common debug pattern of passing a Config value to `fmt.Printf`,
`slog.Debug`, or any other reflection-based formatter:

- **Webhook** (`webhook.Config`): `String`, `GoString`, and `Format`
  drop the URL path, query, and fragment — only `scheme://host` is
  printed. Headers are included with values replaced by `[REDACTED]`
  when the header name (case-insensitive substring) contains `auth`,
  `key`, `secret`, or `token`. Non-matching header names print their
  value verbatim so operators can see non-sensitive trace headers.
- **Loki** (`loki.Config`): `String` and `Format` drop the URL path,
  query, and fragment. `BasicAuth` prints as `BasicAuth{REDACTED}` for
  both `%v` and `%#v`. `BearerToken` and `TenantID` are never printed;
  only the presence of bearer authentication is surfaced (`auth=bearer_token`).
  Custom headers are not printed at all.
- **Syslog** (`syslog.Config`): `String`, `GoString`, and `Format`
  print only `network`, `address`, `tls` (none/tls/mtls marker), and
  `facility`. TLS certificate and key file paths, custom hostname, and
  app name are omitted from the stringer output even though they are
  not secrets — they simply are not useful for debug-log
  disambiguation.
- **Secret references** (`secrets.Ref`): `String` emits
  `ref+SCHEME://[REDACTED]#KEY` — the value is never logged, only the
  scheme and key are surfaced for debugging.
- **OpenBao / HashiCorp Vault configs** (`openbao.Config`,
  `vault.Config`): `String`, `GoString`, and `Format` strip the
  Address URL to scheme+host, print `token=[REDACTED]` (or `unset`
  when empty), and surface the presence of `Namespace` and TLS client
  cert without the values themselves.
- **File output** (`file.Config`): no credential fields. No stringer
  is required; consumer logging of the Config reveals only path,
  permissions, and rotation settings — all non-sensitive.

In-transit error leakage is closed too: HTTP retry-loop errors from
webhook and Loki outputs pass through a `sanitiseClientError` helper
that replaces the URL in any `*url.Error` returned by
`http.Client.Do` with the sanitised scheme+host form. Path tokens
(Slack, Splunk HEC) and query-string credentials no longer appear in
diagnostic log lines produced by failed retries or connection errors.

The `ErrDuplicateDestination` error returned from `WithOutputs` /
`WithNamedOutput` no longer includes the raw destination key, because
that key is URL-path-bearing for webhook and Loki outputs. The error
message names the two conflicting outputs only — enough to identify
the misconfiguration without surfacing token material.

The `fmt.Formatter` interface is implemented on every Config type to
intercept `%+v` (struct-tag reflection) which would otherwise bypass a
`String` method. Consumers who print individual fields directly
(`slog.Info("url", cfg.URL)`) bypass these safeguards; do not do this.

## Software Bill of Materials (SBOM)

Every release includes SBOMs in two formats, published as assets in
the [GitHub Release](https://github.com/axonops/audit/releases):

| Format | Filename | Use Case |
|--------|----------|----------|
| **CycloneDX** | `audit_<version>_sbom.cdx.json` | Vulnerability scanners (Trivy, Grype, Dependency-Track) |
| **SPDX** | `audit_<version>_sbom.spdx.json` | License compliance tools, regulatory reporting |

Both SBOMs list all direct and transitive dependencies across every
module in the repository, including versions and license identifiers.

### Using the SBOM

Scan for vulnerabilities:

```bash
# Download the SBOM from the GitHub release, then:
trivy sbom audit_v0.1.0_sbom.cdx.json
```

Generate a local SBOM from source (requires [syft](https://github.com/anchore/syft)):

```bash
make sbom            # generates CycloneDX + SPDX in sbom/
make sbom-validate   # validates JSON structure
```
