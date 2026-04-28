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

## Static-Analysis Guards

Several security invariants are enforced by static checks, not just code
review. The CI `Hygiene` job invokes each guard target individually;
locally `make check` chains the same set. Contributors SHOULD run
`make check` before pushing.

| Invariant | Enforcement | Bypass mechanism |
|---|---|---|
| `InsecureSkipVerify: true` never appears in production code | `make check-insecure-skip-verify` (CI `Hygiene` job + local `make check`) | Append `// audit:allow-insecure-skip-verify` to the same line as the field assignment. Reserved for documented test helpers; reviewers MUST justify any exemption against the threat model. |
| `replace` directives never appear in `go.mod` | `make check-replace` | None. |
| `TODO` comments must reference an issue | `make check-todos` | Append `//nolint` on the same line — strongly discouraged; requires explicit reviewer justification. |

The `InsecureSkipVerify` rule excludes `*_test.go` files unconditionally.
Tests that require a self-signed CA MUST configure a custom `RootCAs`
pool; they MUST NOT disable verification. The line-grep enforcement
relies on `make fmt-check` running first (which it does, both as the
first step in CI's `Hygiene` job and as the first dependency of
`make check`): `gofmt` collapses any multi-line struct-literal back
onto one line, so a contributor cannot evade the grep by spreading
`InsecureSkipVerify\n: true` across lines.

## Disclosure Policy

We follow coordinated disclosure with a 90-day window:

1. Reporter submits via GitHub Security Advisories
2. We acknowledge and triage within the timelines above
3. We develop and test a fix
4. We publish a patched release and a GitHub Security Advisory
5. Reporter may publish their findings after the advisory is published,
   or after 90 days from the initial report — whichever comes first

## Threat Model

The library's full threat model — actors, assets, trust boundaries,
guarantees, and explicit non-guarantees — lives in
[docs/threat-model.md](docs/threat-model.md). Read it before
deploying to a regulated or hostile environment. Highlights:

- **Actors**: trusted developer (taxonomy author, `AuditEvent` caller),
  trusted operator (`outputs.yaml` + secret store + network policy),
  untrusted upstream caller (event field values), untrusted downstream
  endpoint (SIEM / collector), in-transit attacker, co-located
  attacker (out of scope — see Non-Guarantees).
- **Assets**: audit-trail integrity and confidentiality, operator
  credentials (HMAC salts, bearer tokens, mTLS keys), application
  availability, diagnostic-log integrity.
- **Trust boundaries**: taxonomy YAML is **trusted** (compiled in via
  `go:embed`); `outputs.yaml` and env vars are **trusted-from-disk**
  (operator-owned); event field values are **untrusted** and SHOULD
  flow through `audit.Sanitizer` at the consumer's boundary; network
  egress is **untrusted** and gated by the SSRF block list and TLS
  1.3 default.
- **Guarantees** the library makes (each test-locked): no log
  injection, SSRF block list, TLS 1.3 by default, HMAC tamper
  detection, no credentials in `String()` / `%v` output, at-most-once
  delivery within a process, bounded per-event memory
  (`MaxEventBytes`), no panics escape the package boundary,
  constant-time HMAC verification, init-time fail-fast on hardcoded
  SSRF data.
- **Non-guarantees** (operator MUST NOT rely on these): producer
  backpressure, full memory zeroing of credentials, taxonomy
  integrity at runtime, defence against co-located attackers reading
  process memory, defence against a compromised downstream.

## Scope

If you believe you have found a flaw in the library's own defences
— not in how a consumer uses it — we want to hear about it. Examples
of what we consider in scope:

- A way to bypass the webhook output's SSRF protection so that
  requests reach private networks or published cloud metadata
  endpoints despite the guard being enabled. The guard blocks the
  IPv4 and IPv6 forms listed in [docs/webhook-output.md](docs/webhook-output.md#ssrf-protection)
  and [docs/loki-output.md](docs/loki-output.md#ssrf-protection),
  including IPv4-mapped IPv6 aliases. Rejections carry a typed
  `*SSRFBlockedError` wrapping `ErrSSRFBlocked` so consumers can
  route per-reason metrics without parsing error strings.
  **Limitation:** operators on clouds with IPv6 instance-metadata
  endpoints that are NOT in the block list (e.g. an unverified
  Azure IPv6 IMDS — tracked in [#643](https://github.com/axonops/audit/issues/643))
  MUST NOT rely solely on this guard. Additional mitigations —
  network-level egress filtering, IMDSv2 hop-limit, workload
  identity — remain the operator's responsibility
- A flaw that forces a TLS connection to downgrade below the
  configured minimum version
- The library itself leaking credentials (e.g., webhook auth headers
  appearing in error messages or log output)
- A way to cause the library to consume unbounded memory or CPU
  through crafted taxonomy definitions or configuration, independent
  of the audit data a consumer passes in

### Consumer-supplied event payloads (defence in depth)

Consumer-controlled event data is explicitly out of scope as a
vulnerability class — see the list below. Since v0.x the library
nonetheless caps per-event payload size at the entry point of every
async output (syslog, webhook, Loki) through the `max_event_bytes`
configuration knob (default 1 MiB, range 1 KiB–10 MiB). This is
defence in depth against a buggy or malicious caller: without the cap,
a single oversized event queued in a 10 000-slot buffer could pin
upward of 100 GiB before backpressure. The `Write` entry point
rejects oversized events with `audit.ErrEventTooLarge` (wrapping
`ErrValidation`) and increments the output's drop counter; subsequent
events continue to deliver. The `stdout` output writes synchronously
to `os.Stdout`; the `file` output buffers at a channel but does not
batch or retry-hold events, so per-event bytes are not re-concentrated
into longer-lived structures. Operators with extreme throughput
requirements on `file` should still configure upstream ingestion caps.

### Privacy primitive — Sanitizer interface

For consumers who DO need centralised content scrubbing (PII
redaction, secret masking, panic-value sanitisation), the
`audit.Sanitizer` interface is the integration point. Register one
via `audit.WithSanitizer`; the library invokes it on every
`Audit`/`AuditEvent` call AND on middleware-recovered panic values
before they are re-raised to outer panic handlers. See
`docs/sanitizer.md` for the contract, common patterns, and threat
model. Sanitizer panics are recovered with strict logging
isolation: the diagnostic logger records only field keys and value
TYPES, never raw values.

### Out of scope

The following are normal usage, bugs, or consumer responsibility and
should be reported as regular GitHub issues, not security reports:

- Consumers passing arbitrary data in audit fields without
  configuring a [Sanitizer] — the library records what it is given
  unless an explicit scrubbing hook is registered (see above)
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

## Secrets and Memory Retention

The library resolves secrets from `vault://` / `openbao://` providers
and threads the plaintext values into output configurations. Because
Go strings are immutable and cannot be zeroed in memory, values
persist until the garbage collector reclaims them — which is not
under the library's control. This section documents what the library
does to minimise retention and what operators must do to bound it.

### What the library does

- **Provider token storage.** `secrets/vault` and `secrets/openbao`
  store the auth token as `[]byte` internally (not `string`).
  `Provider.Close()` zeroes the byte slice best-effort. This is
  genuine zeroing; subsequent reads of the slice see `0x00`.
- **HTTP request headers.** Building a Vault request calls
  `req.Header.Set("X-Vault-Token", string(p.token))`, which creates
  an immutable `string` copy of the token bytes. After the response
  is handled, the library `Header.Del`s the entry to drop the
  map-held reference; the underlying string persists until GC. This
  is defence-in-depth, not zeroing.
- **Resolver caches.** `outputconfig.Load()` builds a short-lived
  resolver with in-memory `pathCache` / `refCache` maps to
  deduplicate provider calls within one Load invocation. The
  resolver is local to Load and becomes GC-unreachable at return.
  A deferred `clear()` call drops map-held references before Load
  unwinds to narrow the window before GC.

### What the library cannot do

Resolved plaintext values land in the following output-config fields
and **persist for the auditor's lifetime** as Go strings / byte
slices:

- `loki.Config.BearerToken`, `loki.Config.TenantID`
- `loki.BasicAuth.Password`
- `webhook.Config.Headers` (e.g. `Authorization` values)
- `HMACConfig.SaltValue` (`[]byte` — the library cannot zero this
  because consumers may hold references)

Zeroing these is impossible from inside the library: the strings are
immutable, the byte slices are consumer-reachable, and Go's GC does
not expose a "scrub on free" hook. Memory dumps, core files, and
heap profiles captured while the auditor is running will contain
these values.

### Provider threat models

Each secret provider has a distinct threat model. Choose the
provider whose model matches your deployment:

- **`file://`** (Kubernetes mounted secrets, Docker secrets). The
  path in `outputs.yaml` is the trust boundary — the library
  follows symlinks and reads whatever is at the target. **The
  operator is responsible for filesystem permissions on the
  secret file**; the library does NOT enforce a permission-mode
  check (Kubernetes mounts secrets at 0644 by default;
  enforcement would break the dominant deployment pattern). All
  errors redact the path; an attacker reading library logs
  cannot infer the secret-mount layout from error messages
  alone.
- **`env://`** (process environment). Environment variables are
  visible to any process running as the **same UID** via
  `/proc/PID/environ` (Linux) or equivalent per-platform
  mechanisms. They also appear in process listings when set via
  the `env` command at exec time. For stronger isolation use
  `file://` (filesystem permissions on the secret file) or
  `vault`/`openbao` (out-of-process secret store with audit
  log). All errors redact the variable name.
- **`vault`** / **`openbao`**. Resolution uses TLS; bootstrap
  token / namespace / response body are subject to the bootstrap
  credential threat model documented above.

### Operational mitigation

- Use **short-lived tokens** (TTL ≤ 1 hour where the provider
  supports it).
- Use **workload identity** (AWS IAM roles, Kubernetes service
  accounts, GCP workload identity) where available, so bootstrap
  credentials never touch the library.
- **Restart the auditor** periodically to bound the in-memory
  lifetime of resolved values. A credential exfiltrated from a
  running process remains valid only until the next rotation +
  restart cycle.
- **Do not** build custom diagnostic logging that echoes
  `outputconfig.LoadResult` or raw `Config` structs after
  resolution — the library redacts via `String()` / `GoString()` /
  `%+v`, but ad-hoc reflection will surface the plaintext.

Operator guidance with rotation patterns: see
[docs/secrets.md](docs/secrets.md#memory-retention-and-rotation-strategy).

## Fuzz Testing Coverage

Four untrusted-input parsers have Go fuzz targets that execute on
every release:

- `audit.ParseTaxonomyYAML` (taxonomy YAML parser)
- `outputconfig.Load` (outputs YAML + env substitution + secret resolver)
- `outputconfig.expandEnvString` (`${VAR}` / `${VAR:-default}` expander)
- `secrets.ParseRef` (`ref+scheme://path#key` parser)

Each target is fuzzed for **5 minutes** as a blocking release-gate
step (`fuzz-long` job in `.github/workflows/release.yml`). PR CI
runs each target's committed seed corpus via the regular
`go test` invocation as a regression tripwire.

Any crash input found during fuzzing is committed under
`testdata/fuzz/FuzzXxx/<hash>` and becomes a permanent seed — the
same corruption can never regress without failing CI.

See [CONTRIBUTING.md — Fuzz Testing](CONTRIBUTING.md#fuzz-testing-481)
for local reproduction commands.

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
