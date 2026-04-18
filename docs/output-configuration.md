[&larr; Back to README](../README.md)

# Output Configuration YAML Reference

The output configuration is a YAML file that defines where your audit
events are sent: which outputs to use, how to format events, how to
route events per-output, and which sensitive fields to strip.

This is a complete reference for everything that can go in an
`outputs.yaml` file.

## 📋 Complete Schema

```yaml
version: 1

# ── Auditor Configuration (optional) ────────────────────────
# Core auditor settings. If omitted, sensible defaults are used.

auditor:
  enabled: true                    # default: true (set false to disable auditing)
  queue_size: 10000                # default: 10,000 (max: 1,000,000)
  shutdown_timeout: "5s"              # default: "5s" (max: "60s")
  validation_mode: strict          # "strict" (default), "warn", "permissive"
  omit_empty: false                # default: false

# ── Framework Fields ──────────────────────────────────────
# Identify every event's origin. app_name and host are required.
# Environment variables are supported in all values.

app_name: "my-service"               # REQUIRED: application name
host: "${HOSTNAME:-localhost}"        # REQUIRED: hostname / environment
timezone: "${TZ:-UTC}"               # optional in YAML — auto-detected from system if omitted; always present in output

# ── Standard Field Defaults (optional) ────────────────────
# Deployment-wide default values for reserved standard fields.
# Applied to every event unless the event sets its own value.
# Keys must be reserved standard field names (actor_id, source_ip, etc.).

standard_fields:
  source_ip: "${DEFAULT_SOURCE_IP:-10.0.0.1}"
  actor_id: "${SERVICE_ACCOUNT:-system}"

# ── Global TLS Policy (optional) ──────────────────────────
# Applies to all TLS-enabled outputs (syslog tcp+tls, webhook https)
# that don't specify their own tls_policy. Per-output tls_policy
# overrides this global setting.

tls_policy:
  allow_tls12: false               # default: false (TLS 1.3 only)
  allow_weak_ciphers: false        # default: false

# ── Outputs ─────────────────────────────────────────────────
# Map of named outputs. Each output has a type, optional config,
# optional formatter override, optional event route, and optional
# sensitivity label exclusions.

outputs:

  # ── Stdout Output ─────────────────────────────────────────
  console:
    type: stdout
    # No additional config needed. Writes to os.Stdout.

  # ── File Output ───────────────────────────────────────────
  audit_file:
    type: file
    enabled: true                  # optional, default true — set false to disable
    file:
      path: "${AUDIT_LOG_DIR:-/var/log/audit}/events.log"   # env vars supported
      max_size_mb: 100             # rotate at this size (default: 100)
      max_backups: 5               # keep this many rotated files (default: 5)
      max_age_days: 30             # delete files older than this (default: 30)
      permissions: "0600"          # file permissions (default: "0600")
      compress: true               # gzip rotated files (default: true)
    route:
      exclude_categories:
        - read                     # don't write verbose read events to this file
    exclude_labels:
      - pii                        # strip PII fields before writing

  # ── Syslog Output ─────────────────────────────────────────
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"           # "tcp" (default), "udp", or "tcp+tls"
      address: "${SYSLOG_HOST}:6514"
      app_name: "myapp"            # RFC 5424 APP-NAME (default: "audit")
      facility: "local0"           # syslog facility (default: "local0")
      tls_ca: "/etc/audit/ca.pem"
      tls_cert: "/etc/audit/client-cert.pem"   # for mTLS
      tls_key: "/etc/audit/client-key.pem"     # for mTLS
      max_retries: 10              # reconnection attempts (default: 10)
      # tls_policy:                # TLS version policy
      #   allow_tls12: false       # allow TLS 1.2 (default: TLS 1.3 only)
      #   allow_weak_ciphers: false # allow weaker ciphers with TLS 1.2
    formatter:
      type: cef                    # SIEM-native format
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
    route:
      include_categories:
        - security                 # only security events to SIEM

  # ── Webhook Output ────────────────────────────────────────
  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
      batch_size: 50               # events per batch (default: 100)
      flush_interval: "5s"         # time-based flush (default: "5s")
      timeout: "10s"               # HTTP request timeout (default: "10s")
      max_retries: 3               # retry attempts (default: 3)
      # buffer_size: 10000        # internal buffer; events dropped when full
      # headers:                   # custom HTTP headers
      #   Authorization: "Bearer ${AUDIT_TOKEN}"
      # tls_ca: "/etc/audit/ca.pem"
      # tls_cert: "/etc/audit/client-cert.pem"
      # tls_key: "/etc/audit/client-key.pem"
      # tls_policy:                # TLS version policy
      #   allow_tls12: false
      #   allow_weak_ciphers: false
      # allow_insecure_http: true  # MUST NOT be true in production
      # allow_private_ranges: true # disable SSRF protection (dev only)
    route:
      min_severity: 7              # only high-severity events
    exclude_labels:
      - pii
      - financial                  # strip sensitive fields

  # ── Loki Output ───────────────────────────────────────────
  loki_audit:
    type: loki
    loki:
      url: "https://loki.example.com/loki/api/v1/push"
      tenant_id: "${LOKI_TENANT:-}"
      batch_size: 100                # events per push (default: 100)
      max_batch_bytes: 1048576       # max payload bytes (default: 1 MiB)
      flush_interval: "5s"           # time-based flush (default: "5s")
      timeout: "10s"                 # HTTP request timeout (default: "10s")
      max_retries: 3                 # retry on 429/5xx (default: 3)
      gzip: true                     # gzip compression (default: true)
      labels:
        static:
          environment: "production"
          job: "audit"
        dynamic:                     # all included by default; set false to exclude
          # pid: false               # exclude pid (high cardinality)
      # basic_auth:
      #   username: "loki-writer"
      #   password: "${LOKI_PASSWORD}"
      # bearer_token: "${LOKI_TOKEN}"
      # tls_ca: "/etc/audit/ca.pem"
      # allow_insecure_http: true    # MUST NOT be true in production
      # allow_private_ranges: true   # disable SSRF protection (dev only)
    route:
      include_categories:
        - security
```

## 📋 Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Must be `1`. Schema version for future migration. |
| `app_name` | Yes | Application name. Emitted as a framework field in every event. Max 255 bytes. |
| `host` | Yes | Hostname/environment. Emitted as a framework field. Max 255 bytes. Env vars supported. |
| `timezone` | No | Timezone name (e.g. `UTC`, `America/New_York`). Max 64 bytes. Auto-detected from system when absent. |
| `standard_fields` | No | Map of reserved standard field names to deployment-wide default values. Keys must be [reserved standard field names](../examples/13-standard-fields/#the-solution-reserved-standard-fields). |
| `secrets` | No | Secret provider configuration. Constructs providers from YAML instead of programmatic setup. See [Secrets Configuration](#secrets-configuration). |
| `auditor` | No | Auditor configuration. All fields optional; defaults applied if omitted. |
| `tls_policy` | No | Global TLS policy for all TLS-enabled outputs. Per-output `tls_policy` overrides. Does NOT apply to secret providers — each provider defaults to TLS 1.3 independently. |
| `outputs` | Yes | Map of named outputs. At least one must be defined. Maximum: 100. |

## ⚙️ Logger Configuration

The optional `auditor:` section configures the core auditor. All
fields are optional — omitted fields use sensible defaults.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Set `false` to disable audit logging entirely (no-op auditor). |
| `queue_size` | `10000` | Core async channel capacity (Level 1). Events dropped when full. Maximum: 1,000,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `shutdown_timeout` | `"5s"` | How long `Close()` waits for pending events to flush. Maximum: `"60s"`. |
| `validation_mode` | `"strict"` | `"strict"` rejects unknown fields, `"warn"` logs them, `"permissive"` accepts all. |
| `omit_empty` | `false` | `true` to skip zero-value fields in output. Consumers under compliance regimes that require all registered fields SHOULD leave this `false`. Only applies when no per-output `formatter` is configured — when an explicit formatter is present, the formatter's own `omit_empty` takes precedence. |

All values support environment variable substitution:

```yaml
auditor:
  queue_size: ${AUDIT_QUEUE_SIZE:-10000}
  shutdown_timeout: "${AUDIT_DRAIN_TIMEOUT:-5s}"
  enabled: ${AUDIT_ENABLED:-true}
```

## 🪵 Diagnostic Logger Propagation

The `auditor:` section has no YAML field for the diagnostic logger — a
`*slog.Logger` is a runtime value, not a YAML construct. Configure it
programmatically when loading the output configuration:

```go
logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

result, err := outputconfig.Load(
    ctx,
    data,
    taxonomy,
    outputconfig.WithDiagnosticLogger(logger), // construction-time warnings
)

auditor, err := audit.New(
    audit.WithTaxonomy(taxonomy),
    audit.WithDiagnosticLogger(logger),         // runtime warnings
    audit.WithOutputs(result.Outputs...),
)
```

Pass the same logger to both `outputconfig.WithDiagnosticLogger` and
`audit.WithDiagnosticLogger`. The first routes warnings emitted during
output construction (TLS policy, file permission mode). The second
routes warnings emitted at runtime (connection retries, buffer-full
drops). Using the same logger ensures all library diagnostics reach
one handler.

Supplying only `audit.WithDiagnosticLogger` leaves construction-time
warnings routed through `slog.Default` — a subtle inconsistency if
your application uses a non-default handler. Both options accept nil
(equivalent to `slog.Default`).

## 🔒 Global TLS Policy

The optional `tls_policy:` section sets the default TLS version and
cipher suite policy for all TLS-enabled outputs (syslog with
`network: tcp+tls`, webhook with `https://`). If an output defines its own `tls_policy`, the global `tls_policy`
is ignored entirely for that output — fields are not merged. The
per-output block stands alone, with any omitted fields taking their
defaults (`false`).

| Field | Default | Description |
|-------|---------|-------------|
| `allow_tls12` | `false` | Allow TLS 1.2 connections in addition to TLS 1.3. When `false` (default), only TLS 1.3 is accepted. Set `true` when connecting to legacy infrastructure that does not support TLS 1.3. |
| `allow_weak_ciphers` | `false` | Allow weaker cipher suites when TLS 1.2 is enabled. Has no effect when `allow_tls12` is `false`. SHOULD NOT be enabled unless required by a specific server. |

> ⚠️ **Security:** The default policy (TLS 1.3 only, no weak ciphers)
> is the most secure configuration. Only relax these settings when
> connecting to infrastructure that cannot be upgraded.

Outputs that do not use TLS (file, stdout, syslog with `network: tcp`
or `network: udp`) ignore the global TLS policy.

## 🔐 Secrets Configuration

The optional `secrets:` section configures secret providers
declaratively in YAML, replacing programmatic provider setup via
`WithSecretProvider`. Providers are constructed, used for `ref+`
URI resolution during `Load`, and closed automatically — callers
do not manage their lifecycle.

```yaml
secrets:
  timeout: "15s"
  openbao:
    address: "${BAO_ADDR}"
    token: "${BAO_TOKEN}"
    allow_insecure_http: true    # dev-only — NEVER in production
    allow_private_ranges: true   # Docker internal network
  vault:
    address: "${VAULT_ADDR}"
    token: "${VAULT_TOKEN}"
```

### Reserved keys

| Key | Description |
|-----|-------------|
| `timeout` | Secret resolution timeout. Min `1s`, max `120s`. Default: `10s`. `WithSecretTimeout` takes precedence when set programmatically. |

All other keys under `secrets:` are treated as provider scheme names.
Supported providers: `openbao`, `vault`. Unknown keys are rejected
with an actionable error.

### Provider fields

Both `openbao` and `vault` accept the same configuration fields:

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `address` | Yes | — | Server URL. HTTPS required unless `allow_insecure_http` is set. |
| `token` | Yes | — | Authentication token. Use `${ENV_VAR}` — never hardcode. |
| `namespace` | No | `""` | Namespace prefix (sent as `X-Vault-Namespace` header). |
| `tls_ca` | No | `""` | Path to custom CA certificate PEM file. |
| `tls_cert` | No | `""` | Path to client certificate for mTLS. Must be paired with `tls_key`. |
| `tls_key` | No | `""` | Path to client private key for mTLS. Must be paired with `tls_cert`. |
| `tls_policy` | No | TLS 1.3 only | Per-provider TLS policy. The global `tls_policy` does NOT apply to secret providers. |
| `allow_insecure_http` | No | `false` | Permit `http://` URLs. **MUST NOT be `true` in production.** Plaintext HTTP exposes the authentication token to network observers. Use only for local development with Docker Compose. |
| `allow_private_ranges` | No | `false` | Permit connections to RFC 1918 private addresses and loopback. Required for local development where the provider runs on `127.0.0.1` or a Docker network. Cloud metadata endpoints remain blocked. |

> ⚠️ **Security:** Only environment variable substitution (`${VAR}`)
> is applied in the `secrets:` section — `ref+` secret references are
> NOT resolved (this would be circular since providers must exist
> before secrets can be resolved). Tokens MUST come from environment
> variables.

### Duplicate scheme detection

If the same provider scheme appears in both the YAML `secrets:`
section and a programmatic `WithSecretProvider` call, `Load` returns
an error. Choose one or the other for each provider scheme.

## 📦 Output Block

Every output has these fields (plus the optional `hmac:` block):

| Field | Required | Description |
|-------|----------|-------------|
| `type` | Yes | Output type: `"stdout"`, `"file"`, `"syslog"`, `"webhook"`, or `"loki"` |
| `enabled` | No | `true` (default) or `false`. Disabled outputs are skipped. |
| `[type_name]` | Depends | Type-specific config block. Key must match `type`. Not needed for `stdout`. |
| `formatter` | No | Per-output formatter. Defaults to JSON if omitted. |
| `route` | No | Per-output event filter. Receives all events if omitted. |
| `exclude_labels` | No | List of sensitivity labels to strip from events before delivery. |
| `hmac` | No | Per-output HMAC integrity config. See [HMAC Integrity](hmac-integrity.md). |

## 📝 Formatter Configuration

```yaml
formatter:
  type: json                       # "json" or "cef"

  # JSON-specific fields:
  timestamp: rfc3339nano           # "rfc3339nano" or "unix_ms"
  omit_empty: false                # skip zero-value fields

  # CEF-specific fields:
  vendor: "MyCompany"              # CEF header: vendor name
  product: "MyApp"                 # CEF header: product name
  version: "1.0"                   # CEF header: product version
  omit_empty: false                # skip zero-value extension fields
```

| Field | Applies To | Default | Description |
|-------|-----------|---------|-------------|
| `type` | Both | `"json"` | Format type |
| `timestamp` | JSON only | `"rfc3339nano"` | Timestamp format: `"rfc3339nano"` or `"unix_ms"` |
| `omit_empty` | Both | `false` | Skip fields with zero values |
| `vendor` | CEF only | — | Required for CEF. Organisation name. |
| `product` | CEF only | — | Required for CEF. Application name. |
| `version` | CEF only | — | Required for CEF. Application version. |

> **Note:** Loki outputs do not support custom formatters — they are
> locked to JSON. Specifying a non-JSON `formatter` on a `type: loki`
> output returns an error at config load time. See
> [Loki Output: Formatter Restriction](loki-output.md#formatter-restriction)
> for details.

## 🔀 Event Route Configuration

Routes control which events reach an output. Include and exclude
modes are mutually exclusive.

```yaml
route:
  # Include mode — only matching events delivered:
  include_categories: [security]
  include_event_types: [auth_failure]

  # Exclude mode — all events except matching:
  exclude_categories: [read]
  exclude_event_types: [health_check]

  # Severity filtering (can combine with either mode):
  min_severity: 7                  # minimum severity (0-10)
  max_severity: 10                 # maximum severity (0-10)
```

| Field | Description |
|-------|-------------|
| `include_categories` | Only deliver events in these categories |
| `include_event_types` | Only deliver these specific event types |
| `exclude_categories` | Deliver everything except events in these categories |
| `exclude_event_types` | Deliver everything except these specific event types |
| `min_severity` | Minimum severity threshold (0-10 inclusive) |
| `max_severity` | Maximum severity threshold (0-10 inclusive) |

Include and exclude modes are mutually exclusive — setting both on the
same route causes a startup error.

**Severity filtering is an AND condition** — it combines with whichever
mode you use. An event must pass BOTH the category/event filter AND the
severity filter. For example:

```yaml
# Include mode + severity: only security events with severity 8+
route:
  include_categories: [security]
  min_severity: 8

# Exclude mode + severity: everything except reads, but only severity 5+
route:
  exclude_categories: [read]
  min_severity: 5
```

See [Event Routing](event-routing.md) for detailed examples and
explanations.

## 🔒 Sensitivity Label Exclusion

```yaml
exclude_labels:
  - pii                            # strip all PII-labeled fields
  - financial                      # strip all financial-labeled fields
```

Labels are defined in the taxonomy YAML (see [Taxonomy Reference](taxonomy-validation.md#sensitivity-labels)).
Framework fields (`timestamp`, `event_type`, `severity`, `duration_ms`)
are never stripped.

See [Sensitivity Labels](sensitivity-labels.md) for details.

## 📁 File Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `path` | (required) | File path. Supports `${VAR}` substitution. Parent directory must exist. |
| `max_size_mb` | `100` | Rotate when file reaches this size in MB. Maximum: 10,240 (10 GB). |
| `max_backups` | `5` | Number of rotated files to keep. Maximum: 100. |
| `max_age_days` | `30` | Delete rotated files older than this. Maximum: 365. |
| `permissions` | `"0600"` | File permissions (octal string, must be quoted). |
| `compress` | `true` | Gzip compress rotated files. |
| `buffer_size` | `10000` | Internal async buffer capacity. Maximum: 100,000. |

## 📡 Syslog Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `network` | `"tcp"` | Transport: `"tcp"`, `"udp"`, or `"tcp+tls"`. |
| `address` | (required) | Host:port. Supports `${VAR}` substitution. |
| `app_name` | `"audit"` | RFC 5424 APP-NAME field. |
| `facility` | `"local0"` | Syslog facility. Valid: kern, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, local0-local7. |
| `tls_ca` | — | CA certificate path for TLS verification. |
| `tls_cert` | — | Client certificate path for mTLS. |
| `tls_key` | — | Client key path for mTLS. |
| `buffer_size` | `10000` | Internal async buffer capacity. Maximum: 100,000. |
| `max_retries` | `10` | Reconnection attempts before giving up. |
| `tls_policy` | — | TLS version policy (nested object). |
| `tls_policy.allow_tls12` | `false` | Allow TLS 1.2 in addition to TLS 1.3. |
| `tls_policy.allow_weak_ciphers` | `false` | Allow weaker cipher suites when TLS 1.2 is enabled. |

## 🌐 Webhook Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `url` | (required) | HTTPS endpoint. Must be `https://` unless `allow_insecure_http` is set. |
| `batch_size` | `100` | Events per HTTP POST (Level 2 flush threshold). Maximum: 10,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `buffer_size` | `10000` | Internal async buffer capacity (Level 2). Events dropped when full. Maximum: 1,000,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `flush_interval` | `"5s"` | Flush after this duration even if batch is not full. |
| `timeout` | `"10s"` | HTTP request timeout. |
| `max_retries` | `3` | Retry attempts with exponential backoff. Maximum: 20. |
| `headers` | — | Map of custom HTTP headers added to every request. |
| `tls_ca` | — | CA certificate path for TLS verification. |
| `tls_cert` | — | Client certificate path for mTLS. |
| `tls_key` | — | Client key path for mTLS. |
| `tls_policy` | — | TLS version policy (nested object). |
| `tls_policy.allow_tls12` | `false` | Allow TLS 1.2 in addition to TLS 1.3. |
| `tls_policy.allow_weak_ciphers` | `false` | Allow weaker cipher suites when TLS 1.2 is enabled. |
| `allow_insecure_http` | `false` | Allow `http://` URLs. MUST NOT be `true` in production. |
| `allow_private_ranges` | `false` | Allow private/loopback IP ranges. Disables SSRF protection. |

## 🔶 Loki Output Fields

| Field | Default | Description |
|-------|---------|-------------|
| `url` | (required) | Full Loki push API endpoint. MUST be `https://` unless `allow_insecure_http` is set. Include the path: `/loki/api/v1/push`. |
| `basic_auth.username` | — | HTTP basic auth username. MUST NOT be empty when `basic_auth` is set. MUST NOT be set alongside `bearer_token`. |
| `basic_auth.password` | — | HTTP basic auth password. |
| `bearer_token` | — | Sets `Authorization: Bearer <token>`. MUST NOT be set alongside `basic_auth`. |
| `tenant_id` | — | Sets `X-Scope-OrgID` header for Loki multi-tenancy. |
| `headers` | — | Custom HTTP headers. MUST NOT include `Authorization`, `X-Scope-OrgID`, `Content-Type`, `Content-Encoding`, or `Host`. |
| `labels.static` | — | Constant labels on every stream. Keys MUST match `[a-zA-Z_][a-zA-Z0-9_]*`. Values MUST NOT be empty or contain control characters. |
| `labels.dynamic` | all included | Per-event label toggles. Set to `false` to exclude. Valid keys: `app_name`, `host`, `timezone`, `pid`, `event_type`, `event_category`, `severity`. |
| `gzip` | `true` | Gzip compress push request bodies. Note: YAML key is `gzip`, not `compress`. |
| `batch_size` | `100` | Events per push (Level 2 flush threshold). Maximum: 10,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `max_batch_bytes` | `1048576` | Max uncompressed payload bytes (1 MiB). Min: 1,024. Max: 10,485,760 (10 MiB). |
| `flush_interval` | `"5s"` | Time-based flush trigger. Min: `"100ms"`. Max: `"5m"`. |
| `timeout` | `"10s"` | HTTP request timeout. Min: `"1s"`. Max: `"5m"`. |
| `max_retries` | `3` | Retry attempts on 429/5xx with exponential backoff. Max: 20. |
| `buffer_size` | `10000` | Internal async buffer capacity (Level 2). Events dropped when full. Min: 100. Max: 1,000,000. See [Two-Level Buffering](async-delivery.md#two-level-buffering). |
| `tls_ca` | — | CA certificate path for TLS verification. |
| `tls_cert` | — | Client certificate path for mTLS. MUST be set together with `tls_key`. |
| `tls_key` | — | Client key path for mTLS. MUST be set together with `tls_cert`. |
| `tls_policy.allow_tls12` | `false` | Allow TLS 1.2 in addition to TLS 1.3. |
| `tls_policy.allow_weak_ciphers` | `false` | Allow weaker cipher suites when TLS 1.2 is enabled. |
| `allow_insecure_http` | `false` | Allow `http://` URLs. MUST NOT be `true` in production. |
| `allow_private_ranges` | `false` | Allow private/loopback IP ranges. Disables SSRF protection. |

## 🌍 Environment Variable Substitution

Values support `${VAR}` and `${VAR:-default}` syntax:

```yaml
file:
  path: "${AUDIT_LOG_DIR:-/var/log/audit}/events.log"
syslog:
  address: "${SYSLOG_HOST}:${SYSLOG_PORT:-6514}"
```

Expansion happens after YAML parsing for injection safety — the raw
YAML structure is validated first, then string values are expanded.

## 🔑 Secret Reference Resolution

Any string value in the YAML can be a `ref+SCHEME://PATH#KEY` URI
that resolves to a plaintext secret from OpenBao or HashiCorp Vault
at startup. Secret resolution runs after environment variable
expansion and before output construction.

```yaml
outputs:
  secure_log:
    type: file
    hmac:
      enabled: true
      salt:
        version: "2026-Q1"
        value: "ref+openbao://secret/data/audit/hmac#salt"
      hash: HMAC-SHA-256
    file:
      path: "/var/log/audit/secure.log"
  alerts:
    type: webhook
    webhook:
      url: "https://siem.example.com/audit"
      headers:
        Authorization: "ref+vault://secret/data/siem/creds#authorization_header"
```

To enable resolution, register one or more providers via
`outputconfig.WithSecretProvider`:

```go
import "github.com/axonops/audit/secrets/openbao"

provider, err := openbao.New(&openbao.Config{
    Address: os.Getenv("BAO_ADDR"),
    Token:   os.Getenv("BAO_TOKEN"),
})
if err != nil {
    return fmt.Errorf("openbao provider: %w", err)
}
defer provider.Close()

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithCoreMetrics(metrics),
    outputconfig.WithSecretProvider(provider),
)
```

A ref URI MUST be the entire string value of a YAML field — substring
replacement is not supported. After all resolution passes, a
safety-net scan rejects any remaining `ref+` URIs in the
configuration.

Environment variables and refs compose: `${VAR}` expands first, so a
ref path can be driven by an environment variable:

```yaml
value: "ref+openbao://${BAO_SECRET_PATH:-secret/data/audit/hmac}#salt"
```

See [Secret Provider Integration](secrets.md) for URI syntax, provider
setup, caching, security model, and error reference.

## 🏭 Factory Registry

Output types must be registered before `Load` can create them.
Registration happens via blank imports in your application:

```go
import (
    _ "github.com/axonops/audit/file"
    _ "github.com/axonops/audit/syslog"
    _ "github.com/axonops/audit/webhook"
    _ "github.com/axonops/audit/loki"
)
```

Or register all output types with a single import:

```go
import _ "github.com/axonops/audit/outputs"
```

If an output type's module is not imported, `Load` returns an error
— no output is silently dropped. The `stdout` type is always
available (built into core).

## 📦 Loading Output Configuration

The simplest way to create an auditor from YAML is the
`outputconfig.New` facade — one call, no manual wiring:

```go
//go:embed taxonomy.yaml
var taxonomyYAML []byte

auditor, err := outputconfig.New(ctx, taxonomyYAML, "outputs.yaml", nil)
if err != nil {
    return fmt.Errorf("audit: %w", err)
}
defer func() { _ = auditor.Close() }()
```

For advanced control (custom metrics, secret providers, per-call
factory overrides), use `outputconfig.Load` directly:

```go
//go:embed outputs.yaml
var outputsYAML []byte

result, err := outputconfig.Load(ctx, outputsYAML, taxonomy,
    outputconfig.WithCoreMetrics(metrics),
)
if err != nil {
    return fmt.Errorf("audit config: %w", err)
}

opts := []audit.Option{audit.WithTaxonomy(taxonomy)}
opts = append(opts, result.Options...)
auditor, err := audit.New(opts...)
```

## 📚 Further Reading

- [Progressive Example: File Output](../examples/03-file-output/) — file-specific configuration
- [Progressive Example: Multi-Output](../examples/09-multi-output/) — multiple outputs in one YAML
- [Progressive Example: Capstone](../examples/17-capstone/) — four outputs with HMAC, CEF, Loki, and PII stripping
- [Outputs](outputs.md) — output types and fan-out architecture
- [Event Routing](event-routing.md) — per-output event filtering
- [Sensitivity Labels](sensitivity-labels.md) — per-output field stripping
- [Secret Provider Integration](secrets.md) — ref+ URI syntax, OpenBao/Vault setup, security model
- [API Reference: outputconfig.Load](https://pkg.go.dev/github.com/axonops/audit/outputconfig#Load)
