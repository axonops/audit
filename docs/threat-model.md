# Threat Model

This document defines the security model for `github.com/axonops/audit`:
who the library is defending against, what assets it protects, what
guarantees it provides, and where its boundaries are.

[SECURITY.md](../SECURITY.md) summarises this model and points back here
for the full picture. If you are integrating the library, read this
document before deploying to a regulated or hostile environment.

## Audience

- **Consumers** — Go application developers integrating the library to
  emit audit events. They write taxonomy YAML, call the API, and own
  the application process.
- **Operators** — engineers deploying the consumer's application. They
  own `outputs.yaml`, environment variables, network policy, and the
  filesystem on which the application runs.
- **Auditors** — security or compliance staff verifying the audit
  trail's integrity and answering "did this event reach the SIEM?".

## Actors

| Actor | Position | Capabilities |
|---|---|---|
| **Trusted developer** | Inside the consumer codebase | Defines the taxonomy, calls `AuditEvent`, owns the Go process. Trusted to write a correct taxonomy and to not deliberately misuse the API. |
| **Trusted operator** | Inside the deployment environment | Owns `outputs.yaml`, env vars, the secret store, network egress policy, and TLS material. Trusted to keep credentials out of source control and to follow the per-output Production Checklists. |
| **Untrusted upstream caller** | HTTP client / message-bus producer / RPC peer | Source of values that flow into event fields (`actor_id`, `source_ip`, etc.). Their input is sanitised at the boundary the consumer chooses; the library does NOT trust this input. |
| **Untrusted downstream endpoint** | Webhook receiver / Loki host / syslog collector | The destination of audit events. May be compromised, replaced, or misconfigured. Receives only what the library sends; cannot influence what the library does beyond the response-handling defenders documented per output. |
| **In-transit attacker** | Network between consumer and downstream | Can observe and tamper with cleartext traffic. TLS 1.3 by default; per-event HMAC available for tamper detection beyond TLS termination. |
| **Co-located attacker** | Same host, different UID | Can read the process's memory through OS-mediated channels (`/proc/PID/mem`, ptrace, core dumps) if the kernel security model permits. The library does NOT defend against this attacker — see Non-Guarantees. |
| **Insider with code-push rights** | Inside the consumer codebase | Can modify the taxonomy or the audit emit sites. Out of scope. The audit trail is one input to detecting this attacker; the library is not their barrier. |
| **Supply-chain attacker** | Compromised dependency, build pipeline, or release artefact | Could ship a malicious library version that exfiltrates secrets, weakens HMAC, or silently drops events. Mitigations live one layer above this model: GoReleaser builds, Cosign keyless OIDC artefact signing (#482), pinned dependency versions, fuzz-gated release pipeline (#481), GitHub build-provenance attestations on every release artefact (`gh attestation verify`), and `go mod verify` against `sum.golang.org` for library consumers. See [SECURITY.md §Software Bill of Materials](../SECURITY.md#software-bill-of-materials-sbom) for the full supply-chain story. Operators SHOULD verify the Cosign signature on release artefacts before deployment in regulated environments. |

## Assets

| Asset | Why it matters |
|---|---|
| **Audit trail integrity** | Auditors must be able to trust that events were not silently modified, dropped, or fabricated in transit. |
| **Audit trail confidentiality** | Audit events frequently carry PII, internal identifiers, error context — all must travel over authenticated, encrypted channels. |
| **Operator credentials** | HMAC salts, webhook bearer tokens, Vault/OpenBao tokens, mTLS keys, Loki BasicAuth passwords. Their exposure permits forging events, accessing the SIEM directly, or impersonating the application to upstream APIs. |
| **Application availability** | The library MUST NOT introduce a denial-of-service vector. A misbehaving downstream endpoint or oversized event must not block, OOM, or panic the consumer process. |
| **Diagnostic-log integrity** | The library's own `slog`-routed warnings must not become a log-injection or info-leak channel. |

## Trust Boundaries

```
       Trusted developer ──┐
                           ▼
             ┌──────────────────────────┐
             │ Taxonomy YAML (embedded) │ ← TRUSTED (compiled in)
             └──────────────────────────┘
                           │
                           ▼
       Trusted operator ──┐
                          ▼
             ┌─────────────────────────────┐
             │ outputs.yaml + env vars +   │ ← TRUSTED-FROM-DISK (operator-owned)
             │ secret-store URLs           │
             └─────────────────────────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   Auditor        │
                 └──────────────────┘
                          │
   ┌──────────────────────┼──────────────────────────┐
   │                      │                          │
   ▼                      ▼                          ▼
event values     framework fields       per-event metadata
(UNTRUSTED;      (TRUSTED;              (UNTRUSTED if caller-supplied;
sanitised at     deterministic from     framework-set when from ctx)
caller's         taxonomy + auditor
boundary)        config)
   │                      │                          │
   └──────────────────────┴──────────────────────────┘
                          │
                          ▼
              ┌──────────────────────┐
              │ Formatter (JSON/CEF) │
              └──────────────────────┘
                          │
                          ▼
              ┌──────────────────────┐
              │ Output transports    │ → TLS 1.3 by default
              │ (file/syslog/webhook │ → per-event HMAC optional
              │  /loki/stdout)       │
              └──────────────────────┘
                          │
                          ▼
              Untrusted downstream endpoint
```

| Boundary | Trust direction |
|---|---|
| Taxonomy YAML | TRUSTED. Consumed at compile time via `go:embed`; cannot be modified at runtime. The developer writes it; the auditor MAY review it. |
| `outputs.yaml` | TRUSTED-FROM-DISK. The operator owns the file. The library validates structure, rejects unknown fields, and resolves `${ENV_VAR}` / `ref+SCHEME://path` references using the registered secret providers. |
| Env vars | TRUSTED-FROM-DISK. Same trust as `outputs.yaml`. **Any process with the same EUID, or any process holding `CAP_SYS_PTRACE` or root, can read `/proc/PID/environ`** (mode 0400, owned by the process EUID on Linux). Prefer file:// or vault:// for sensitive values where this matters; see SECURITY.md. |
| Field values | UNTRUSTED. The library does not assume `actor_id` or `source_ip` are sanitised; consumers SHOULD route untrusted values through `audit.Sanitizer` (see [docs/sanitizer.md](sanitizer.md)). |
| Network egress | UNTRUSTED. SSRF protection blocks loopback / link-local / cloud metadata / CGNAT / private ranges by default; explicit opt-in flags relax for specific deployment patterns. |

## Guarantees

The library MAKES the following defensive guarantees. Each is exercised by named tests; see the linked sections for verification.

| Guarantee | How it's enforced | Test reference |
|---|---|---|
| **No log injection via field values** | All event values flow through type-aware formatters; control bytes in field values are escaped per JSON / CEF rules. Diagnostic-logger error messages strip control bytes from echoed input (see #481). | `format_test.go:TestWriteJSONString` and `TestWriteJSONString_QuickCheck` (property-based fuzz over invalid UTF-8 + control bytes). |
| **SSRF block list for HTTP outputs** | Webhook + Loki dial control rejects loopback, link-local, cloud metadata (IPv4 IMDS + IPv6 `fd00:ec2::254`), CGNAT (`100.64.0.0/10`), deprecated site-local (`fec0::/10`), private ranges, IPv4-mapped IPv6 forms. Returns typed `*SSRFBlockedError` with stable `Reason` label. | `ssrf_test.go:TestCheckSSRFIP_Blocked`, `TestCheckSSRFIP_AllowPrivateRanges`, `TestCheckSSRFIP_IPv4MappedIPv6`, `TestCheckSSRFIP_BlocksAllKnownMetadataEndpoints`, `TestCheckSSRFIP_BlocksDeprecatedSiteLocalIPv6`, `TestSSRFBlockedError_TypedAccessPattern`; webhook integration in `webhook/webhook_external_test.go:TestWebhookOutput_SSRFBlocked`; BDD coverage in `tests/bdd/features/webhook_output.feature` (SSRF scenarios). |
| **TLS 1.3 by default; explicit downgrade required** | `TLSPolicy` zero value enables TLS 1.3 only. Operators wanting TLS 1.2 must opt in with `min_version: "1.2"`. mTLS supported on every TLS-capable output. | `tls_policy_test.go:TestTLSPolicy_Apply_NilReceiver_DefaultsTLS13` and `TestTLSPolicy_Apply_ZeroValue_DefaultsTLS13`; per-output TLS scenarios live in `tests/bdd/features/webhook_output.feature`, `loki_config.feature`, and `syslog_output.feature`. |
| **HMAC tamper detection (optional)** | Per-output HMAC with 6 NIST-approved algorithms; salt versioning; `_hmac_v` is part of the authenticated region (since #473). External verifiers strip only `_hmac` to recompute. | `hmac_test.go:TestComputeHMAC_*` algorithm coverage; BDD scenarios in `tests/bdd/features/hmac_integrity.feature` and `loki_hmac.feature` for end-to-end emission and external verification. |
| **No credentials in `String()` / `%v` / `%+v` output** | All credential-bearing config types (`HMACConfig`, `vault.Config`, `openbao.Config`, `webhook.Config.Headers`, `loki.Config.BearerToken` / `BasicAuth`, `syslog.Config.TLSCert`) implement `Stringer` / `Format` / `GoString` to redact paths and values. Prevents accidental leak via `log.Printf("%+v")`. | `loki/config_test.go:TestConfigString_Redaction` and equivalents in `webhook/`, `syslog/`, `secrets/vault/`, `secrets/openbao/`. |
| **At-most-once delivery within a process** | Events that reach the buffer are delivered to every enabled output unless the process crashes. Buffer-full returns `ErrQueueFull` to the caller; never silently drops. | `audit_test.go:TestLogger_Audit_BufferFull` (legacy name, retained pre-#457) plus `validation_error_test.go:TestErrQueueFull_NotErrValidation` for the sentinel-discrimination contract. |
| **Bounded per-event memory** | Every async output (syslog, webhook, loki) caps `MaxEventBytes` at `Write()` entry (default 1 MiB, range 1 KiB–10 MiB). Oversized events are rejected with `ErrEventTooLarge`. Prevents `~10 events × MaxEventBytes` memory from blowing up the buffer. | `webhook/webhook_max_event_bytes_test.go`, `syslog/syslog_max_event_bytes_test.go`, `loki/loki_max_event_bytes_test.go`. |
| **No panics escape the package boundary** | `MustNewEventKV` and `MustRegisterOutputFactory` panic only on programmer error at literal-input call sites; every runtime error path returns `error`. Middleware recovers panics, sanitises them via the Sanitizer, and re-raises. | `middleware_sanitizer_test.go:TestMiddleware_SanitizePanic_AppliedToReRaise` and `_SanitiserPanicsFailOpen` cover the recover/sanitise/re-raise sequence; `convenience_test.go:TestNewEventKV_OddArgs_ReturnsError` and `TestNewEventKV_NonStringKey_ReturnsError` lock the non-Must error path. |
| **Constant-time HMAC verification** | `VerifyHMAC` rejects structural problems (empty value, wrong length for the algorithm's hash size, non-lowercase-hex) before reaching `hmac.Equal`. Well-formed-but-wrong values reach the constant-time compare; structural rejects (length, hex charset) precede it. | `hmac_test.go:TestVerifyHMAC_RejectsMalformedEarly_NotTimingSensitive` and `TestVerifyHMAC_ValidInputs_ReachesConstantTimeCompare`. |
| **Init-time fail-fast on hardcoded SSRF data** | `mustParseCIDR` / `mustParseIP` panic at package load if any committed CIDR or IP literal fails to parse. A source corruption or stdlib regression fails loudly, not silently. | `ssrf_internal_test.go:TestSSRFInit_CGNATBlockNotNil`, `TestSSRFInit_DeprecatedSiteLocalBlockNotNil`, `TestSSRFInit_AWSIPv6MetadataIPNotNil`. |

## Non-Guarantees

The library does NOT defend against the following. Operators MUST NOT rely on it for these properties.

| Non-guarantee | Why | Recommended mitigation |
|---|---|---|
| **Backpressure on the producer** | When the buffer fills, `AuditEvent` returns `ErrQueueFull`. The library does not sleep, retry, or block to apply pressure to the producer. | The consumer decides: log to stderr, increment a metric, slow down, or fail the request. See [docs/async-delivery.md](async-delivery.md). |
| **Full memory zeroing of credentials** | Go strings are immutable; the runtime may copy them to multiple heap locations. The library best-effort zeroes provider `[]byte` token storage on `Provider.Close()` and drops HTTP header map entries after each request, but cannot guarantee full erasure. | Operate on the assumption that credentials linger in process memory for the auditor's lifetime. Rotate frequently; restart on rotation; favour short-lived tokens (Vault dynamic creds, OpenBao TTL <1h). See [SECURITY.md §Secrets and Memory Retention](../SECURITY.md#secrets-and-memory-retention). |
| **Taxonomy integrity at runtime** | The taxonomy is embedded at compile time; the library doesn't re-validate it on every event. A compromised binary could ship a permissive taxonomy that accepts forged events. | Out of scope. Defend with code review, signed releases (Cosign keyless OIDC, see #482), and a separate auditor reviewing the taxonomy YAML. |
| **Preventing reads of process memory by co-located attackers** | A same-UID attacker (or root on the host) can read process memory via `/proc/PID/mem` or core dumps regardless of what the library does. | OS-level isolation: kernel hardening (`yama.ptrace_scope = 1`), seccomp, AppArmor / SELinux profiles, dedicated UID per service, deny core dumps in production (`ulimit -c 0` or systemd `LimitCORE=0`). |
| **Defense against a compromised downstream** | A compromised SIEM or webhook receiver receives every audit event the operator sends to it. The library protects the consumer, not the destination. | Operator hardens the destination separately. HMAC tamper-detection is asymmetric: a compromised receiver that does not hold the salt CANNOT forge new events under that salt — integrity is preserved even when confidentiality is lost. HMAC alone does NOT mitigate drop or replay attacks; pair with sequence numbers, monotonic timestamps, or downstream deduplication if those are in your model. A second operator can re-compute the HMAC on the receiver's stored events without trusting the receiver. |
| **Side-channel resistance for sanitisers** | `audit.Sanitizer` runs in user code; the library cannot guarantee the consumer's regex masking or hashing is timing-safe. | Sanitisers SHOULD use `hmac.Equal`-style primitives when comparing for masking decisions. Documented in [docs/sanitizer.md](sanitizer.md). |
| **Atomic durability across crashes** | A crash mid-`Output.Write` can leave a partial event on disk (file output) or in flight (network outputs). | File output uses `O_APPEND` so partial writes don't corrupt prior events; network outputs lose in-flight events on crash. For stronger durability use a syslog relay with disk spooling, or a Loki agent with persistent buffering. |
| **Audit-trail completeness across process restarts** | Events buffered in the core queue or per-output buffers at the moment of SIGKILL, kernel OOM, or panic-induced exit are lost. The library does not persist its in-memory queue. | Operators requiring durability across crashes MUST run a syslog relay or Loki agent with disk spooling between the auditor and the final SIEM, or accept the residual data loss as part of the threat model. |

## Compliance and Regulated Environments

The library's primitives compose into deployments that meet common compliance requirements; the library itself does not certify against any specific framework.

| Framework / requirement | Library primitive | Operator responsibility |
|---|---|---|
| **PCI DSS 10.x (audit trail)** | Async delivery + buffer-full error returned to caller; HMAC integrity; no creds in String output. | Configure delivery to a dedicated SIEM; set `MaxEventBytes` and buffer sizes; rotate HMAC salts per a documented policy. |
| **HIPAA §164.312(b) audit controls** | Per-output `exclude_labels` for PHI stripping by output (compliance output drops `phi`-labelled fields; ops output keeps them); Sanitizer interface for content scrubbing. | Define `phi` / `pii` labels on every PHI-bearing field in the taxonomy; configure compliance outputs with `exclude_labels: [phi]`. |
| **SOC 2 CC4.1 (monitoring)** | Diagnostic logger surfaces output drops, retries, reconnects; Metrics interface exposes per-output delivery counters. | Wire `audit.Metrics` into Prometheus / OpenTelemetry; alert on `output_delivery_total{status="error"}` / drop counters. |
| **GDPR Art. 25 (data protection by design)** | Sanitizer interface; per-output exclude-labels; HMAC for integrity. | Classify every PII field in the taxonomy with the appropriate label; configure outputs with `exclude_labels` to enforce data minimisation per processing purpose. |
| **FedRAMP / NIST SP 800-53 AU-9 (protection of audit information)** | Constant-time HMAC verification; HTTPS-only secret providers by default (the `AllowInsecureHTTP` opt-in MUST NOT be set in regulated environments); SSRF block list; TLS 1.3 default. | Configure mTLS on every output; rotate HMAC salts; harden the SIEM; verify the release-artefact Cosign signature pre-deployment. |
| **ISO 27001 A.12.4 (logging and monitoring)** | Async delivery + buffer-full error returned to caller; per-output `exclude_labels` for content minimisation; HMAC integrity; diagnostic-logger surface for output drops, retries, reconnects. | Wire `audit.Metrics` into the operator's SIEM; alert on output drop / delivery-error counters; document the HMAC salt rotation policy and the operator runbook. |

The library's [SECURITY.md](../SECURITY.md) lists every defender and is the authoritative reference. This document defines the model; that one defines the implementation surface and reporting process.

## Reviewing This Model

This threat model is reviewed:

- Before every milestone release tag (mandated by CONTRIBUTING.md release checklist).
- Whenever a new output, transport, or trust boundary is added.
- Whenever the SSRF block list, TLS policy, or credential-handling code changes.
- On any reported vulnerability — see [SECURITY.md](../SECURITY.md) for the report channel.

Updates land alongside the change that motivated them; the model is not a snapshot maintained separately from the code.
