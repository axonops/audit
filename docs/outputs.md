[&larr; Back to README](../README.md)

# Output Types and Fan-Out

- [What Are Outputs?](#what-are-outputs)
- [Available Outputs](#available-outputs)
- [File Output](#file-output)
- [Syslog Output](#syslog-output)
- [Webhook Output](#webhook-output)
- [Loki Output](#loki-output)
- [Stdout Output](#stdout-output)
- [Per-Output Features](#per-output-features)
- [Fan-Out Architecture](#fan-out-architecture)

## 🔍 What Are Outputs?

Outputs are where your audit events end up after validation and
serialisation. go-audit can send the same event to multiple outputs
at once — a local file for long-term retention, a syslog server for
your SIEM, and a webhook for real-time alerting, all simultaneously.

### Optional Interfaces

Output implementations may satisfy additional optional interfaces:

| Interface | Purpose |
|-----------|---------|
| `DestinationKeyer` | Duplicate destination detection at construction |
| `DeliveryReporter` | Output handles its own delivery metrics |
| `MetadataWriter` | Receives structured event metadata (event type, severity, category, timestamp) alongside pre-serialised bytes |

`MetadataWriter` is used by outputs that need structured access to
per-event fields — for example, Loki uses event_type and severity as
stream labels. Outputs that don't implement it receive plain `Write()`
calls with no overhead.

## ❓ Why Multiple Outputs?

Different teams need audit events in different places, in different
formats, with different levels of detail:

- **Security team** — needs events in [CEF format](cef-format.md) in their SIEM, filtered to security categories
- **Compliance** — needs a complete, unfiltered file with all fields for regulatory retention
- **Operations** — needs high-severity events pushed to a webhook for alerting
- **External partners** — needs events with [PII fields stripped](sensitivity-labels.md) before delivery

Each output can have its own formatter, [event routing](event-routing.md)
filter, and [sensitivity label exclusions](sensitivity-labels.md).

## 📋 Available Outputs

| Output | Module | Transport | Key Features |
|--------|--------|-----------|--------------|
| **File** | `go-audit/file` | Local filesystem | Size-based rotation, gzip compression, backup retention, configurable permissions |
| **Syslog** | `go-audit/syslog` | TCP, UDP, TCP+TLS | RFC 5424 format, mTLS client certs, automatic reconnection |
| **Webhook** | `go-audit/webhook` | HTTPS | Batched delivery, retry with backoff, SSRF protection, custom headers |
| **Loki** | `go-audit/loki` | HTTPS | Stream labels, gzip compression, multi-tenancy, retry with backoff, SSRF protection |
| **Stdout** | `go-audit` (core) | Standard output | Built into the core module — no additional dependency needed |

---

## 📁 File Output

Writes one event per line to a local file. Rotates automatically when
the file reaches the configured size. Old files are compressed with
gzip and retained up to the configured count and age.

### YAML Configuration

```yaml
outputs:
  audit_log:
    type: file
    file:
      path: "${AUDIT_LOG_PATH:-./audit.log}"  # env vars supported
      max_size_mb: 100        # rotate at this size (default: 100, max: 10,240)
      max_backups: 5          # rotated files to keep (default: 5, max: 100)
      max_age_days: 90        # delete older than this (default: 30, max: 365)
      permissions: "0600"     # file permissions (default: "0600", must be quoted)
      compress: true          # gzip rotated files (default: true)
    route:                    # optional — filter which events reach this output
      exclude_categories:
        - read
    exclude_labels:           # optional — strip fields with these sensitivity labels
      - pii
```

### Validation

- The parent directory of `path` must exist — the library creates
  the file but not the directory.
- **Symlinks are rejected.** The library resolves the parent directory
  path and rejects symlinks to prevent path traversal attacks. This
  check occurs on the first write.
- The `permissions` field must be quoted in YAML (e.g., `"0600"`) —
  unquoted `0600` is parsed as the integer 384 by YAML.

Install: `go get github.com/axonops/go-audit/file`

---

## 📡 Syslog Output

Sends events as RFC 5424 syslog messages over TCP, UDP, or TCP+TLS.
The connection is established immediately when the output is created —
the syslog server must be reachable at startup. TCP and TLS
connections are re-established automatically on failure.

### YAML Configuration

```yaml
outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"           # "tcp" (default), "udp", or "tcp+tls"
      address: "${SYSLOG_ADDR}:6514"  # required
      app_name: "myapp"            # RFC 5424 APP-NAME (default: "audit")
      facility: "local0"           # syslog facility (default: "local0")
      tls_ca: "/etc/audit/ca.pem"  # CA certificate for TLS verification
      tls_cert: "/etc/audit/client-cert.pem"  # client cert for mTLS
      tls_key: "/etc/audit/client-key.pem"    # client key for mTLS
      tls_policy:                  # TLS version policy
        allow_tls12: false         # allow TLS 1.2 (default: false — TLS 1.3 only)
        allow_weak_ciphers: false  # weaker ciphers with TLS 1.2 (default: false)
      max_retries: 10              # reconnection attempts (default: 10)
    formatter:
      type: cef
      vendor: "MyCompany"          # CEF header field (recommended, default: empty)
      product: "MyApp"             # CEF header field (recommended, default: empty)
      version: "1.0"               # CEF header field (recommended, default: empty)
    route:
      include_categories:
        - security
```

**CEF formatter fields:** `vendor`, `product`, and `version` are
recommended but not required. If omitted, the CEF header positions
are empty strings — the event is still valid CEF but less useful for
SIEM correlation. Set them to identify your organisation and
application in SIEM dashboards.

**UDP limitation:** Messages exceeding the network MTU are silently
truncated. Use TCP or TLS for events with large payloads.

**Valid facility values:** `kern`, `user`, `mail`, `daemon`, `auth`,
`syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`,
`local0` through `local7`.

Install: `go get github.com/axonops/go-audit/syslog`

---

## 🌐 Webhook Output

Batches events as newline-delimited JSON (NDJSON) and POSTs them to
an HTTPS endpoint. Failed batches are retried with exponential
backoff.

### YAML Configuration

```yaml
outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"  # required, must be https://
      batch_size: 50              # events per batch (default: 100, max: 10,000)
      buffer_size: 10000          # internal buffer capacity (default: 10,000, max: 1,000,000)
      flush_interval: "5s"        # flush after this duration (default: "5s")
      timeout: "10s"              # HTTP request timeout (default: "10s")
      max_retries: 3              # retry attempts (default: 3, max: 20)
      headers:                    # custom HTTP headers
        Authorization: "Bearer my-token"
        X-Custom-Header: "my-value"
      tls_ca: "/etc/audit/ca.pem"           # CA cert for TLS verification
      tls_cert: "/etc/audit/client-cert.pem" # client cert for mTLS
      tls_key: "/etc/audit/client-key.pem"   # client key for mTLS
      tls_policy:                 # TLS version policy
        allow_tls12: false        # allow TLS 1.2 (default: false — TLS 1.3 only)
        allow_weak_ciphers: false # weaker ciphers with TLS 1.2 (default: false)
      # allow_insecure_http: true # MUST NOT be true in production
      # allow_private_ranges: true # SSRF protection — enable only for local dev
    route:
      min_severity: 7             # only high-severity events
    exclude_labels:
      - pii
      - financial
```

**Custom headers:** Use `headers` to add authentication tokens,
correlation IDs, or any custom HTTP headers to every request. Header
values are plain strings — use environment variables for secrets
(e.g., read from `os.Getenv` in your Go code before passing to the
programmatic API).

**Security:** HTTPS is required by default. `allow_insecure_http`
MUST NOT be enabled in production — plaintext HTTP exposes
credentials in request headers to network observers. Private and
loopback IP ranges are blocked unless `allow_private_ranges` is
explicitly enabled (SSRF protection).

**Delivery:** At-least-once — a batch may be delivered more than once
if the server accepts the payload but the acknowledgement is lost.
Design your receiver to handle duplicate batches.

**Buffer drops:** If the webhook's internal buffer fills (events
arrive faster than batches can be sent), events are dropped and
`webhook.Metrics.RecordWebhookDrop()` is called. Increase
`buffer_size` if you see drops.

Install: `go get github.com/axonops/go-audit/webhook`

---

## 🔶 Loki Output

Pushes audit events to a [Grafana Loki](https://grafana.com/oss/loki/)
instance via the HTTP Push API. Events are batched, grouped into
streams by label values, gzip-compressed, and delivered with
exponential backoff retry.

### Why Loki?

Loki excels for audit logging because:

- **Stream labels** derived from event metadata (event_type, severity,
  category) make audit events queryable via LogQL without parsing
  every log line
- **Multi-tenancy** via `X-Scope-OrgID` keeps different applications
  or environments isolated in a shared Loki cluster
- **Grafana integration** provides dashboards, alerting, and LogQL
  exploration out of the box

### YAML Configuration

```yaml
outputs:
  loki_audit:
    type: loki
    loki:
      url: "https://loki.example.com/loki/api/v1/push"  # required, full path
      tenant_id: "my-service"      # X-Scope-OrgID header (optional)
      batch_size: 100              # events per push (default: 100, max: 10,000)
      max_batch_bytes: 1048576     # max payload bytes (default: 1 MiB, max: 10 MiB)
      buffer_size: 10000           # internal buffer capacity (default: 10,000, min: 100, max: 1,000,000)
      flush_interval: "5s"         # flush after this duration (default: "5s")
      timeout: "10s"               # HTTP request timeout (default: "10s")
      max_retries: 3               # retry attempts for 429/5xx (default: 3, max: 20)
      gzip: true                   # gzip compression (default: true)
      labels:
        static:                    # constant labels on every stream
          job: "audit"
          environment: "production"
        dynamic:                   # per-event labels — all included by default
          # Set to false to exclude (all are included when omitted):
          # pid: false             # exclude pid (high cardinality)
          # severity: false        # exclude severity
      basic_auth:                  # mutually exclusive with bearer_token
        username: "loki-writer"
        password: "${LOKI_PASSWORD}"
      # bearer_token: "${LOKI_TOKEN}"  # alternative to basic_auth
      headers:                     # custom HTTP headers
        X-Custom-Header: "my-value"
      tls_ca: "/etc/audit/ca.pem"
      tls_cert: "/etc/audit/client-cert.pem"
      tls_key: "/etc/audit/client-key.pem"
      tls_policy:
        allow_tls12: false         # TLS 1.3 only by default
        allow_weak_ciphers: false
      # allow_insecure_http: true  # MUST NOT be true in production
      # allow_private_ranges: true # SSRF protection — enable only for local dev
    route:
      include_categories:
        - security
    exclude_labels:
      - pii
```

### Stream Labels

Loki indexes events by **stream labels** — key-value pairs that
identify a log stream. go-audit generates labels from three sources:

| Source | Example | Set at |
|--------|---------|--------|
| Static labels | `job="audit"`, `environment="prod"` | Config time |
| Framework fields | `app_name="myapp"`, `host="prod-01"`, `pid="12345"` | Logger construction |
| Per-event metadata | `event_type="user_create"`, `severity="6"`, `event_category="write"` | Each event |

**Controlling dynamic labels:** Set any dynamic label to `false` in
the config to exclude it from stream labels. Excluded fields still
appear in the JSON log line — they are just not indexed as labels.

```yaml
labels:
  dynamic:
    pid: false       # exclude pid from labels (high cardinality)
    severity: false   # exclude severity from labels
```

**Querying in Grafana:** Events are queryable by label selectors and
log line content:

```logql
{event_type="auth_failure", severity="8"} | json | actor_id="alice"
```

### Security

- **HTTPS required** by default. `allow_insecure_http` MUST NOT be
  enabled in production.
- **SSRF protection** blocks private and loopback IP ranges unless
  `allow_private_ranges` is explicitly enabled.
- **Redirects are rejected** to prevent open-redirect SSRF attacks.
- **Restricted headers** (`Authorization`, `Content-Type`,
  `X-Scope-OrgID`, `Content-Encoding`, `Host`) cannot be set via
  the `headers` map — use the dedicated config fields instead.
- **Credential redaction** — `Config.String()` and `fmt.Sprintf("%+v", cfg)`
  never expose passwords or bearer tokens.

### Delivery Guarantees

**At-least-once** — a batch may be delivered more than once if the
server accepts the payload but the acknowledgement is lost.

**Retry on 429/5xx** — exponential backoff (100ms base, 2x factor, 5s
cap) with [0.5, 1.0) jitter. `Retry-After` headers on 429 responses
are respected (capped at 30s).

**No retry on 4xx** (except 429) — client errors indicate a
configuration problem, not a transient failure. Events are dropped and
`loki.Metrics.RecordLokiDrop()` is called.

**Buffer drops:** If the internal buffer fills, events are dropped and
`loki.Metrics.RecordLokiDrop()` is called. Increase `buffer_size` if
you see drops.

Install: `go get github.com/axonops/go-audit/loki`

---

## 💻 Stdout Output

Writes events to standard output. Built into the core module — no
additional `go get` needed. Useful for local development, debugging,
and piping to other tools.

### YAML Configuration

```yaml
outputs:
  console:
    type: stdout
```

No additional configuration fields are needed.

---

## 🔀 Per-Output Features

Every output supports these optional features:

| Feature | Where to Configure | Documentation |
|---------|-------------------|---------------|
| **Formatter** | `formatter:` block on each output | [JSON](json-format.md), [CEF](cef-format.md) |
| **Event routing** | `route:` block on each output | [Event Routing](event-routing.md) |
| **Sensitivity labels** | `exclude_labels:` on each output | [Sensitivity Labels](sensitivity-labels.md) |
| **Enable/disable** | `enabled: false` on each output | Toggle without removing config |

## 📡 Fan-Out Architecture

The drain goroutine serialises each event once per unique format and
delivers to all outputs in sequence. Each output is independent —
a failure in one output does not block or affect delivery to others.

## 📚 Further Reading

- [Progressive Example: File Output](../examples/04-file-output/)
- [Progressive Example: Multi-Output](../examples/05-multi-output/)
- [Progressive Example: CRUD API](../examples/11-crud-api/) — five outputs in one application
- [Output Configuration YAML](output-configuration.md) — full YAML reference
