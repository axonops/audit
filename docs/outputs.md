[&larr; Back to README](../README.md)

# Output Types and Fan-Out

## What Are Outputs?

Outputs are the destinations where audit events are delivered after
validation and serialisation. go-audit sends events to all configured
outputs simultaneously — this is called fan-out. A single audit event
can be written to a local file for retention, a syslog server for your
SIEM, and a webhook endpoint for real-time alerting, all at once.

## Why Multiple Outputs?

Audit events serve different consumers with different needs:

- **Security team** — needs events in CEF format in their SIEM, filtered to security-relevant categories
- **Compliance** — needs a complete, unfiltered local file for regulatory retention
- **Operations** — needs high-severity events pushed to an alerting webhook
- **Development** — needs stdout output during local testing

Each output can have its own formatter, event routing filter, and
sensitivity label exclusion rules.

## Available Outputs

| Output | Module | Transport | Key Features |
|--------|--------|-----------|--------------|
| **File** | `go-audit/file` | Local filesystem | Size-based rotation, gzip compression, backup retention, configurable permissions |
| **Syslog** | `go-audit/syslog` | TCP, UDP, TCP+TLS | RFC 5424 format, mTLS client certs, automatic reconnection |
| **Webhook** | `go-audit/webhook` | HTTPS | Batched delivery, retry with backoff, SSRF protection |
| **Stdout** | `go-audit` (core) | Standard output | Development and debugging; no additional module needed |

## Configuration

### YAML (recommended)

```yaml
version: 1
outputs:
  audit_file:
    type: file
    file:
      path: "/var/log/audit/events.log"
      max_size_mb: 100
      max_backups: 10

  siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "syslog.example.com:6514"
      tls_ca: "/etc/audit/ca.pem"
    formatter:
      type: cef
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"

  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
      batch_size: 50
    route:
      min_severity: 7
```

### File Output

Writes JSON or CEF lines to a local file. Rotates automatically when
the file reaches `max_size_mb`. Old files are retained up to
`max_backups` count and `max_age_days`, then deleted. Compressed
backups use gzip (enabled by default). Default permissions: `0600`.

The parent directory must exist before the logger starts.

### Syslog Output

Sends events as RFC 5424 syslog messages over TCP, UDP, or TCP+TLS.
The connection is established immediately when the output is created
— the syslog server must be reachable at startup. TCP and TLS
connections are re-established automatically on write failure (up to
`max_retries` attempts). mTLS is supported via `tls_cert` and
`tls_key` fields.

### Webhook Output

Batches events into JSON arrays and POSTs them to an HTTPS endpoint.
Failed batches are retried with exponential backoff. HTTPS is required
by default — plaintext HTTP is only permitted when `allow_insecure_http`
is explicitly set (development only). Private and loopback IP ranges
are blocked unless `allow_private_ranges` is enabled (SSRF protection).

Delivery semantics are at-least-once: a batch may be delivered more
than once if the server accepts the payload but the acknowledgement
is lost.

### Stdout Output

Writes events to `os.Stdout` (or any `io.Writer`). Included in the
core module — no additional dependency needed. Useful for local
development and debugging.

## Fan-Out Architecture

Events pass through a single drain goroutine that handles serialisation
and delivery. Each output can have:
- A different **formatter** (JSON for files, CEF for SIEM)
- A different **event route** (security events only, high-severity only)
- Different **sensitivity label exclusions** (strip PII from external outputs)

The drain goroutine serialises each event once per unique format and
delivers to all outputs. Outputs do not need to be thread-safe — the
single drain goroutine is the only writer.

## Further Reading

- [Progressive Example: File Output](../examples/03-file-output/)
- [Progressive Example: Multi-Output](../examples/04-multi-output/)
- [Event Routing](event-routing.md) — per-output filtering
- [CEF Format](cef-format.md) — SIEM integration format
- [YAML Configuration](yaml-configuration.md) — output config file reference
