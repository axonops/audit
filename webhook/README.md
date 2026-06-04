# webhook — batched HTTPS webhook output

[![Go Reference][godoc-badge]][godoc]

Posts batched audit events to an HTTPS endpoint as NDJSON (or whatever
content-type the configured formatter declares), with exponential
backoff retry on 5xx/429, SSRF protection, mTLS support, and graceful
shutdown. Implements the [`audit.Output`][audit-output] interface.

> **Module path**: `github.com/axonops/audit/webhook`
> **Status**: pre-release (v0.x)
> **Documentation**: [webhook-output.md][docs] · [examples/07-webhook-output][example]

## Why

A generic HTTPS webhook is the path of least resistance for SIEMs and
log platforms that don't speak syslog: Datadog, New Relic,
SumoLogic-by-HTTP, Elastic via an HTTP ingest pipeline, custom
PagerDuty / Slack alerting, or any internal HTTP intake service. You
get TLS, authentication via custom headers (Bearer, API key, HMAC
signature), and HTTP's well-defined retry semantics (429 with
`Retry-After`, 5xx with backoff) without writing a transport layer.

Use webhook when the destination is HTTP-only, when you need
fine-grained header control (per-tenant `X-Tenant-ID`, signed
`X-Hub-Signature`), or as the lowest-common-denominator integration
for SaaS endpoints. Use [`syslog`](../syslog/) for SIEMs that speak
RFC 5424 (lower overhead, no JSON envelope), [`loki`](../loki/) for
LogQL-native querying, or [`splunk`](../splunk/) for direct Splunk
HEC delivery.

## Install

```bash
go get github.com/axonops/audit/webhook
```

Requires Go 1.26+. See the [main README](../README.md) for transitive
dependencies.

## Quick start

```go
import (
    "os"

    "github.com/axonops/audit"
    "github.com/axonops/audit/webhook"
)

out, err := webhook.New(&webhook.Config{
    URL:     "https://ingest.example.com/audit",
    Headers: map[string]string{
        "Authorization": "Bearer " + os.Getenv("WEBHOOK_TOKEN"),
    },
})
if err != nil {
    return err
}

tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
if err != nil {
    return err
}
auditor, err := audit.New(
    audit.WithTaxonomy(tax),
    audit.WithAppName("my-service"),
    audit.WithHost("host-01"),
    audit.WithOutputs(out),
)
if err != nil {
    return err
}
defer func() { _ = auditor.Close() }()
```

HTTPS is mandatory by default; `Config.AllowInsecureHTTP` (or
`allow_insecure_http: true` in YAML) exists only for local development.
The endpoint MUST be reachable at construction time (TCP dial + TLS
handshake under a 5 s budget) unless `Config.DisableStartupVerification`
is set (or `verify_on_startup: false` in YAML — note the inversion:
the YAML key is the positive form) for sidecar startup ordering.

## YAML configuration

```yaml
version: 1
app_name: "my-service"
host: "${HOSTNAME}"

outputs:
  alerts:
    type: webhook
    webhook:
      url: "https://ingest.example.com/audit"
      headers:
        Authorization: "Bearer ${WEBHOOK_TOKEN}"
        X-Tenant-ID: "acme-corp"
      batch_size: 100              # default — events per HTTP POST
      flush_interval: "5s"         # default
      timeout: "10s"               # default — full request/response budget
      max_retries: 3               # default — 5xx/429 retry attempts
      buffer_size: 10000           # default — events dropped when full
      max_batch_bytes: 1048576     # 1 MiB — flush when payload reaches this
      max_event_bytes: 1048576     # 1 MiB — reject oversized events
      tls:
        ca:   "/etc/audit/ca.pem"
        cert: "/etc/audit/client-cert.pem"   # for mTLS
        key:  "/etc/audit/client-key.pem"    # for mTLS
        # key_password: "${TLS_KEY_PASSWORD}"  # PKCS#8 v2 encrypted key
        # allow_tls12: false                   # default — TLS 1.3 only
```

A blank import registers the `webhook` output type with the YAML
loader:

```go
import _ "github.com/axonops/audit/webhook"
```

## Configuration reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | *(required)* | HTTPS endpoint (or `http://` if `allow_insecure_http: true`). URLs with embedded credentials (`user:pass@`) are rejected — use `headers` for auth. |
| `headers` | map[string]string | — | Custom HTTP headers added to every request. Header values whose names contain `auth`, `key`, `secret`, `token`, `cookie`, `password`, `credential`, `signature`, `hmac`, or `session` are redacted in debug output. CRLF in either name or value is rejected. |
| `tls.ca` | string | — | Path to a PEM CA bundle for server verification. Falls back to the system root pool when empty. |
| `tls.cert` | string | — | Path to the client certificate for mTLS. Must be set with `tls.key`. |
| `tls.key` | string | — | Path to the client private key for mTLS. Supports PKCS#8 v2 encrypted keys via `tls.key_password`. PKCS#1 DEK-Info legacy keys are refused. |
| `tls.key_password` | string | — | Password for an encrypted `tls.key`. Use a secret reference (`ref+openbao://…`, env var) in production. |
| `tls.allow_tls12` | bool | `false` | When `false`, only TLS 1.3. Set `true` for TLS 1.2 fallback. |
| `batch_size` | int | `100` | Maximum events per HTTP POST. Max `10000`. |
| `max_batch_bytes` | int | `1048576` (1 MiB) | Payload-byte flush threshold (sum of event lengths). A single event exceeding this is sent in its own request; it is never dropped. Range `1024`–`10485760` (1 KiB–10 MiB). |
| `max_event_bytes` | int | `1048576` (1 MiB) | Per-event size cap at `Write` entry. Events exceeding this are rejected with `audit.ErrEventTooLarge`. Defends against consumer-controlled memory pressure. Range `1024`–`10485760`. |
| `flush_interval` | duration | `5s` | Maximum time between flushes. The timer resets after every flush (size- or timer-triggered). |
| `timeout` | duration | `10s` | Full request/response timeout. The transport-level `ResponseHeaderTimeout` is derived as `max(timeout/2, 1s)` so a small `timeout` cannot wedge a per-stage budget below what a real TLS handshake needs. |
| `max_retries` | int | `3` | Total delivery attempts for 5xx and 429 responses. `Retry-After` is honoured for 429. Max `20`. |
| `buffer_size` | int | `10000` | Internal async channel capacity. Events dropped when full; `OutputMetrics.RecordDrop` is called. Max `1000000`. |
| `allow_insecure_http` | bool | `false` | Permit `http://` URLs. MUST NOT be `true` in production — plaintext HTTP exposes Authorization headers to network observers. |
| `allow_private_ranges` | bool | `false` | Disable SSRF protection for RFC 1918 private and loopback ranges. Cloud-metadata IPs (169.254.169.254 etc.) remain blocked regardless. |
| `verify_on_startup` | bool | `true` | When `true`, `New` performs a TCP dial and — for `https://` — a TLS handshake before returning. Set `false` for sidecars. |
| `startup_verification_timeout` | duration | `5s` | Probe budget. Ignored when `verify_on_startup: false`. |

## Authentication

The webhook output does not bake in any specific authentication
scheme — set the appropriate header:

```yaml
headers:
  Authorization: "Bearer ${API_TOKEN}"      # OAuth2 / generic bearer
  # Authorization: "Splunk ${HEC_TOKEN}"    # Splunk HEC literal scheme
  # X-API-Key: "${API_KEY}"                 # API-key services
  # X-Hub-Signature-256: …                  # add via a custom middleware
```

For HMAC request signing (`X-Hub-Signature-256` etc.) the signature
depends on the request body, which means it can't be set as a static
header — implement a custom output or proxy in front of the webhook.

## Delivery model

Events are buffered in memory and batched as a single HTTP POST when
any of these thresholds is reached:

- `batch_size` events are queued
- accumulated payload reaches `max_batch_bytes`
- `flush_interval` elapses since the last flush
- `Close` is called

Failed batches retry with exponential backoff on 5xx and 429
responses. 4xx other than 429 are non-retryable — the batch is
dropped and `RecordError` is recorded.

Delivery semantics are **at-least-once**: a batch may be delivered
more than once if the server accepts the payload but the
acknowledgement is lost. Consumers requiring exactly-once should
deduplicate on the event's content hash or a consumer-defined idempotency key.

## SSRF protection

By default the webhook output refuses to connect to RFC 1918 private
ranges, loopback, link-local, multicast, and cloud-metadata IPs
(169.254.169.254 etc.). `AllowPrivateRanges: true` opts back in for
private addresses but cloud-metadata IPs remain blocked unconditionally.

## See also

- [Full output reference][docs] — batching architecture, NDJSON
  payload structure, HMAC integrity, SSRF policy, retry semantics
- [Worked example][example] — `outputs.yaml` + `main.go` with an
  embedded HTTP receiver so the example runs without external services
- [TLS policy](../docs/output-configuration.md#tls) — TLS 1.3-only
  defaults, TLS 1.2 fallback, weak-cipher policy
- [HMAC integrity](../docs/hmac-integrity.md) — tamper-evident audit
  trails configured per-output
- Related outputs:
  [`syslog`](../syslog/) (RFC 5424 — when the destination speaks syslog),
  [`splunk`](../splunk/) (Splunk HEC — purpose-built for Splunk),
  [`loki`](../loki/) (Grafana Loki — purpose-built for LogQL),
  [`file`](../file/) (local file with rotation)

[godoc]: https://pkg.go.dev/github.com/axonops/audit/webhook
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/webhook.svg
[audit-output]: https://pkg.go.dev/github.com/axonops/audit#Output
[docs]: ../docs/webhook-output.md
[example]: ../examples/07-webhook-output/
