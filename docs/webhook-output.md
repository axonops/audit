[← Back to Output Types](outputs.md)

# Webhook Output — Detailed Reference

The webhook output batches audit events as
[NDJSON](https://github.com/ndjson/ndjson-spec) (newline-delimited
JSON) and POSTs them to an HTTPS endpoint. Failed batches are retried
with exponential backoff. Private and loopback addresses are blocked
by default (SSRF protection).

- [Why Webhook for Audit Logging?](#why-webhook-for-audit-logging)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [NDJSON Format](#ndjson-format)
- [Complete Configuration Reference](#complete-configuration-reference)
- [Authentication](#authentication)
- [TLS Configuration](#tls-configuration)
- [Batching and Delivery](#batching-and-delivery)
- [Retry and Error Handling](#retry-and-error-handling)
- [SSRF Protection](#ssrf-protection)
- [Buffer Drops](#buffer-drops)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [Production Configuration](#production-configuration)
- [Troubleshooting](#troubleshooting)
- [Related Documentation](#related-documentation)

## Why Webhook for Audit Logging?

Webhooks deliver audit events to any HTTP endpoint in real time — no
protocol-specific infrastructure required:

- **Real-time alerting** — push high-severity events to PagerDuty,
  Slack, or custom alerting pipelines
- **Universal integration** — any system with an HTTP endpoint can
  receive audit events (Elasticsearch, Datadog, custom APIs)
- **Batched efficiency** — multiple events per HTTP request reduces
  overhead compared to per-event delivery
- **Standard format** — NDJSON is supported by all major log aggregators

## Quick Start

```bash
go get github.com/axonops/go-audit/webhook
```

```yaml
# outputs.yaml
version: 1
app_name: "my-app"
host: "my-host"
outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
```

```go
import _ "github.com/axonops/go-audit/webhook"  // registers "webhook" factory
```

**[→ Progressive example with embedded HTTP receiver](../examples/07-webhook-output/)**

## How It Works

```mermaid
flowchart LR
    A[AuditEvent] --> B[Drain goroutine]
    B --> C[JSON serialize]
    C --> D[Buffer channel]
    D --> E[Batch loop]
    E -->|count/timer/close| F[Build NDJSON]
    F --> G[HTTP POST]
    G -->|2xx| H[Success]
    G -->|5xx/429| I[Retry with backoff]
    G -->|4xx| J[Drop batch]
```

1. `AuditEvent()` enqueues the event in the logger's internal buffer
2. The drain goroutine serialises the event and sends it to the
   webhook's buffer channel
3. The batch loop accumulates events until a flush trigger fires
4. Events are joined as NDJSON and POSTed to the configured URL
5. On transient failure (5xx, 429), the batch is retried with
   exponential backoff
6. On permanent failure (4xx), the batch is dropped

## NDJSON Format

Each HTTP request body contains one JSON object per line:

```
{"timestamp":"...","event_type":"auth_login","severity":5,...}\n
{"timestamp":"...","event_type":"user_create","severity":5,...}\n
```

The Content-Type header is `application/x-ndjson`.

NDJSON is:
- **Streamable** — receivers can process lines as they arrive
- **Efficient** — no wrapping array or delimiters beyond `\n`
- **Standard** — supported by Elasticsearch Bulk API, Loki, Datadog,
  and most log aggregators

## Complete Configuration Reference

| Field | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `url` | string | *(required)* | — | HTTP endpoint. MUST be `https://` unless `allow_insecure_http` is true |
| `batch_size` | int | `100` | 1–10,000 | Maximum events per HTTP request |
| `buffer_size` | int | `10,000` | 1–1,000,000 | Internal async buffer capacity. Events dropped when full |
| `flush_interval` | duration | `"5s"` | — | Maximum time between batch flushes |
| `timeout` | duration | `"10s"` | — | HTTP request timeout (full request/response lifecycle) |
| `max_retries` | int | `3` | 1–20 | Retry count for 5xx and 429 responses. Values <= 0 default to 3 |
| `headers` | map | *(none)* | — | Custom HTTP headers on every request |
| `tls_ca` | string | *(none)* | — | Path to CA certificate for server verification |
| `tls_cert` | string | *(none)* | — | Path to client certificate for mTLS |
| `tls_key` | string | *(none)* | — | Path to client private key for mTLS |
| `tls_policy` | object | *(nil — TLS 1.3 only)* | — | TLS version and cipher policy |
| `tls_policy.allow_tls12` | bool | `false` | — | Allow TLS 1.2 fallback |
| `tls_policy.allow_weak_ciphers` | bool | `false` | — | Allow weaker cipher suites with TLS 1.2 |
| `allow_insecure_http` | bool | `false` | — | Permit `http://` URLs. MUST NOT be true in production |
| `allow_private_ranges` | bool | `false` | — | Disable SSRF protection for private/loopback ranges |

### Validation Rules

- `url` MUST NOT be empty and MUST be a valid URL
- URL scheme MUST be `http` or `https`
- HTTPS is required unless `allow_insecure_http` is true
- URL MUST NOT contain embedded credentials (use `headers` instead)
- Header names and values MUST NOT contain CRLF characters
- `tls_cert` and `tls_key` MUST both be set or both empty
- `batch_size`, `buffer_size`, `max_retries` are rejected if above
  their upper bounds

## Authentication

Use custom HTTP headers for authentication:

### Bearer Token

```yaml
webhook:
  url: "https://ingest.example.com/audit"
  headers:
    Authorization: "Bearer ${WEBHOOK_TOKEN}"
```

### Splunk HEC

```yaml
webhook:
  url: "https://splunk.internal:8088/services/collector/event"
  headers:
    Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"
```

### API Key

```yaml
webhook:
  url: "https://api.example.com/v1/audit"
  headers:
    X-API-Key: "${API_KEY}"
```

> **Note:** Header values containing `auth`, `key`, `secret`, or
> `token` (case-insensitive) are automatically redacted in log output
> to prevent credential leakage.

## TLS Configuration

### Server Verification Only

```yaml
webhook:
  url: "https://ingest.example.com/audit"
  tls_ca: "/etc/audit/ca.pem"
```

### Mutual TLS (mTLS)

```yaml
webhook:
  url: "https://ingest.example.com/audit"
  tls_ca: "/etc/audit/ca.pem"
  tls_cert: "/etc/audit/client-cert.pem"
  tls_key: "/etc/audit/client-key.pem"
```

### TLS Version Policy

```yaml
webhook:
  url: "https://legacy-endpoint.internal/audit"
  tls_policy:
    allow_tls12: true
    allow_weak_ciphers: false
```

> **Warning:** Enabling `allow_tls12` widens the attack surface.
> `allow_weak_ciphers` MUST NOT be enabled in production.

> **Note:** TLS certificates are loaded once at output construction.
> Certificate rotation requires restarting the application.

## Batching and Delivery

### Flush Triggers

A batch is flushed when ANY of these conditions is met:

| Trigger | Config | Default |
|---------|--------|---------|
| Event count reaches `batch_size` | `batch_size` | 100 |
| Timer reaches `flush_interval` | `flush_interval` | 5s |
| `logger.Close()` called | — | Final flush |

The timer resets after every flush, whether triggered by count or timer.

### Delivery Guarantee

**At-least-once delivery.** A batch may be delivered more than once if
the server accepts the payload but the HTTP acknowledgement is lost
(network timeout, connection reset). Design your receiver to handle
duplicate batches with idempotent processing.

### Request Structure

Each POST request contains:

| Header | Value |
|--------|-------|
| `Content-Type` | `application/x-ndjson` |
| Custom headers | From `headers:` config |

Body: one JSON object per line (NDJSON), terminated with `\n`.

## Retry and Error Handling

| Response | Action | Retried? |
|----------|--------|----------|
| **2xx** | Success — batch delivered | No |
| **429** (Too Many Requests) | Retry with backoff | Yes |
| **5xx** (Server Error) | Retry with backoff | Yes |
| **4xx** (not 429) | Drop batch — configuration or auth error | No |
| **3xx** (Redirect) | Rejected — SSRF protection blocks redirects | No |

### Backoff Parameters

| Parameter | Value |
|-----------|-------|
| Base delay | 100ms |
| Maximum delay | 5s |
| Backoff factor | 2x per attempt |
| Jitter | Random multiplier in [0.5, 1.0) via `crypto/rand` |
| Max attempts | `max_retries` (total attempts including initial) |

```mermaid
flowchart TD
    A[POST batch] --> B{Response?}
    B -->|2xx| C[Success]
    B -->|429/5xx| D{Retries left?}
    D -->|Yes| E[Backoff sleep]
    E --> A
    D -->|No| F[Drop batch]
    B -->|4xx| F
    B -->|3xx redirect| F
```

## SSRF Protection

The webhook output blocks requests to private and loopback addresses
by default, preventing
[Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
attacks:

| Blocked range | CIDR | Always blocked? |
|--------------|------|-----------------|
| Loopback | `127.0.0.0/8` | Unless `allow_private_ranges` |
| Private (A) | `10.0.0.0/8` | Unless `allow_private_ranges` |
| Private (B) | `172.16.0.0/12` | Unless `allow_private_ranges` |
| Private (C) | `192.168.0.0/16` | Unless `allow_private_ranges` |
| Link-local | `169.254.0.0/16` | **Always** (includes cloud metadata) |
| Cloud metadata | `169.254.169.254` | **Always** (even with `allow_private_ranges`) |

Additional protections:
- **Redirects rejected** — HTTP redirects are never followed
- **Keep-alives disabled** — prevents DNS rebinding attacks
- **Credentials in URL rejected** — `https://user:pass@host` returns
  an error; use `headers` instead

## Buffer Drops

The webhook's internal buffer has a fixed capacity (`buffer_size`,
default 10,000). When full, new events are **dropped** and
`webhook.Metrics.RecordWebhookDrop()` is called.

Common causes:
- Webhook endpoint is down and retries are exhausting capacity
- Event volume exceeds the endpoint's processing speed
- `flush_interval` is too long for the event rate

Fix: increase `buffer_size`, reduce `flush_interval`, or scale the
receiving endpoint.

## Metrics and Monitoring

The webhook output provides an optional `Metrics` interface:

```go
type Metrics interface {
    RecordWebhookDrop()                                   // event dropped (buffer full)
    RecordWebhookFlush(batchSize int, dur time.Duration)  // batch delivered
}
```

Register your implementation before calling `outputconfig.Load`. This
replaces the default factory registered by the blank import. If you
don't need webhook-specific metrics, the blank import
`_ "github.com/axonops/go-audit/webhook"` is sufficient.

```go
audit.RegisterOutputFactory("webhook", webhook.NewFactory(myWebhookMetrics))
```

### What to Monitor

| Metric | Condition | Action |
|--------|-----------|--------|
| `RecordWebhookDrop` rate > 0 | Events being lost | Increase `buffer_size`, check endpoint health |
| `RecordWebhookFlush` duration > timeout | Requests timing out | Increase `timeout`, check network latency |
| `RecordWebhookFlush` batch_size = max | Batches always full | Increase `batch_size` or decrease `flush_interval` |

## Production Configuration

### Minimum Secure Configuration

```yaml
outputs:
  audit_alerts:
    type: webhook
    webhook:
      url: "https://${WEBHOOK_ENDPOINT}/audit"
      headers:
        Authorization: "Bearer ${WEBHOOK_TOKEN}"
      timeout: "10s"
      max_retries: 3
```

### High-Volume Configuration

```yaml
outputs:
  audit_ingest:
    type: webhook
    webhook:
      url: "https://ingest.internal/audit"
      batch_size: 500
      buffer_size: 100000
      flush_interval: "2s"
      timeout: "30s"
      max_retries: 5
      tls_ca: "/etc/audit/tls/ca.pem"
```

### Multi-Destination Configuration

```yaml
outputs:
  # High-severity alerts to PagerDuty
  pagerduty:
    type: webhook
    webhook:
      url: "https://events.pagerduty.com/v2/enqueue"
      headers:
        Content-Type: "application/json"
    route:
      min_severity: 8

  # All events to Elasticsearch
  elasticsearch:
    type: webhook
    webhook:
      url: "https://elastic.internal:9200/audit-events/_bulk"
      batch_size: 200
      flush_interval: "3s"
```

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `audit: webhook url must not be empty` | Missing `url` in config | Add the `url` field to the webhook block |
| `audit: webhook url must be https (got "http"); set AllowInsecureHTTP for testing` | Using `http://` without flag | Use `https://` or add `allow_insecure_http: true` (dev only) |
| `audit: webhook url must not contain credentials; use Headers for auth` | Embedded user:pass in URL | Move credentials to `headers:` block |
| `audit: ssrf: dial blocked` | SSRF protection blocked private/loopback address | Add `allow_private_ranges: true` (dev only) |
| Events not arriving | Buffer full, events being dropped | Check `RecordWebhookDrop`; increase `buffer_size` |
| Batches rejected with 401 | Auth token expired or invalid | Update the `Authorization` header value |
| Batches rejected with 413 | Payload too large | Decrease `batch_size` |
| High latency, timeouts | Endpoint slow or unreachable | Increase `timeout`; check endpoint health |

## Related Documentation

- [Output Types Overview](outputs.md) — summary of all five outputs
- [Output Configuration Reference](output-configuration.md) — YAML field tables
- [Progressive Example](../examples/07-webhook-output/) — working code with embedded HTTP receiver
- [NDJSON Specification](https://github.com/ndjson/ndjson-spec) — payload format
- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) — SSRF attack reference
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [Async Delivery](async-delivery.md) — buffer sizing and graceful shutdown
