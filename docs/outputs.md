[&larr; Back to README](../README.md)

# Output Types and Fan-Out

## What Are Outputs?

Outputs are where your audit events end up after validation and
serialisation. go-audit can send the same event to multiple outputs
at once — a local file for long-term retention, a syslog server for
your SIEM, and a webhook for real-time alerting, all simultaneously.

## Why Multiple Outputs?

Different teams need audit events in different places, in different
formats, with different levels of detail:

- **Security team** — needs events in [CEF format](cef-format.md) in their SIEM, filtered to security categories
- **Compliance** — needs a complete, unfiltered file with all fields for regulatory retention
- **Operations** — needs high-severity events pushed to a webhook for alerting
- **External partners** — needs events with [PII fields stripped](sensitivity-labels.md) before delivery

Each output can have its own formatter, [event routing](event-routing.md)
filter, and [sensitivity label exclusions](sensitivity-labels.md).

## Available Outputs

| Output | Module | Transport | Key Features |
|--------|--------|-----------|--------------|
| **File** | `go-audit/file` | Local filesystem | Size-based rotation, gzip compression, backup retention, configurable permissions |
| **Syslog** | `go-audit/syslog` | TCP, UDP, TCP+TLS | RFC 5424 format, mTLS client certs, automatic reconnection |
| **Webhook** | `go-audit/webhook` | HTTPS | Batched delivery, retry with backoff, SSRF protection |
| **Stdout** | `go-audit` (core) | Standard output | Built into the core module — no additional dependency needed |

---

## File Output

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
      max_size_mb: 100        # rotate at 100 MB (default: 100)
      max_backups: 5          # keep 5 rotated files (default: 5)
      max_age_days: 90        # delete files older than 90 days (default: 30)
      permissions: "0600"     # file permissions (default: "0600")
      compress: true          # gzip rotated files (default: true)
    route:                    # optional — filter which events reach this output
      exclude_categories:
        - read
    exclude_labels:           # optional — strip fields with these sensitivity labels
      - pii
```

The parent directory of `path` must exist before the logger starts —
the library creates the file but not the directory.

Install: `go get github.com/axonops/go-audit/file`

---

## Syslog Output

Sends events as RFC 5424 syslog messages over TCP, UDP, or TCP+TLS.
The connection is established immediately when the output is created.
TCP and TLS connections are re-established automatically on failure.

### YAML Configuration

```yaml
outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"           # "tcp" (default), "udp", or "tcp+tls"
      address: "${SYSLOG_ADDR}:6514"
      app_name: "myapp"            # RFC 5424 APP-NAME (default: "audit")
      tls_ca: "/etc/audit/ca.pem"  # CA certificate for TLS verification
      tls_cert: "/etc/audit/client-cert.pem"  # client cert for mTLS
      tls_key: "/etc/audit/client-key.pem"    # client key for mTLS
      max_retries: 10              # reconnection attempts (default: 10)
    formatter:
      type: cef                    # SIEM-native format
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
    route:
      include_categories:
        - security
```

**UDP limitation:** Messages exceeding the network MTU are silently
truncated. Use TCP or TLS for events with large payloads.

Install: `go get github.com/axonops/go-audit/syslog`

---

## Webhook Output

Batches events as newline-delimited JSON (NDJSON) and POSTs them to an
HTTPS endpoint. Failed batches are retried with exponential backoff.

### YAML Configuration

```yaml
outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
      batch_size: 50              # events per batch (default: 100)
      flush_interval: "5s"        # flush after 5 seconds (default: "5s")
      timeout: "10s"              # HTTP request timeout (default: "10s")
      max_retries: 3              # retry attempts (default: 3)
      # allow_insecure_http: true # MUST NOT be true in production
      # allow_private_ranges: true # SSRF protection — enable only for local dev
    route:
      min_severity: 7             # only high-severity events
```

**Security:** HTTPS is required by default. `allow_insecure_http`
MUST NOT be enabled in production — plaintext HTTP exposes
credentials in request headers to network observers. Private and
loopback IP ranges are blocked unless `allow_private_ranges` is
explicitly enabled.

**Delivery:** At-least-once — a batch may be delivered more than once
if the server accepts the payload but the acknowledgement is lost.
Design your receiver to handle duplicate batches.

Install: `go get github.com/axonops/go-audit/webhook`

---

## Stdout Output

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

## Per-Output Features

Every output supports these optional features:

| Feature | Where to Configure | Documentation |
|---------|-------------------|---------------|
| **Formatter** | `formatter:` block on each output | [JSON](json-format.md), [CEF](cef-format.md) |
| **Event routing** | `route:` block on each output | [Event Routing](event-routing.md) |
| **Sensitivity labels** | `exclude_labels:` on each output | [Sensitivity Labels](sensitivity-labels.md) |
| **Enable/disable** | `enabled: false` on each output | Toggle without removing config |

## Fan-Out Architecture

The drain goroutine serialises each event once per unique format and
delivers to all outputs in sequence. Each output is independent —
a failure in one output does not block or affect delivery to others.

## Further Reading

- [Progressive Example: File Output](../examples/03-file-output/)
- [Progressive Example: Multi-Output](../examples/04-multi-output/)
- [Progressive Example: CRUD API](../examples/09-crud-api/) — five outputs in one application
- [YAML Configuration](output-configuration.md) — output config file reference
