# splunk — Splunk HTTP Event Collector (HEC) output

[![Go Reference][godoc-badge]][godoc]

Posts audit events to a Splunk indexer (Splunk Enterprise or Splunk
Cloud) via the HTTP Event Collector with gzip compression, full HEC
error-code handling, exponential backoff, and optional indexer
acknowledgement for at-least-once delivery. Implements the
[`audit.Output`][audit-output] interface.

> **Module path**: `github.com/axonops/audit/splunk`
> **Status**: pre-release (v0.x)
> **Documentation**: [splunk-output.md][docs] · [examples/09-splunk-output][example]

## Why

Splunk is the dominant enterprise SIEM and security data platform. The
HTTP Event Collector is its purpose-built ingestion path — token-auth,
indexed-field extraction at the HEC layer, CIM (Common Information
Model) compatibility for cross-source correlation, and indexer
acknowledgement for compliance-grade durability. You could push events
to Splunk via syslog or a generic webhook, but the HEC `/event`
envelope (`sourcetype`, `index`, `host`, `fields`) and `/services/collector/ack`
are first-class and unavailable through the other paths.

Use the splunk output when Splunk is your destination, when you need
CIM-compliant event shape for the security data model, or when you
need indexer acknowledgement (`AckMode: required`) for at-least-once
delivery. Use [`webhook`](../webhook/) when the destination is any
other HTTPS endpoint, [`syslog`](../syslog/) for SIEMs (including
Splunk via a syslog forwarder) that prefer RFC 5424, or
[`loki`](../loki/) for Grafana-native log storage.

## Install

```bash
go get github.com/axonops/audit/splunk
```

Requires Go 1.26+. See the [main README](../README.md) for transitive
dependencies.

## Quick start

```go
import (
    "os"

    "github.com/axonops/audit"
    "github.com/axonops/audit/splunk"
)

out, err := splunk.New(&splunk.Config{
    URL:        "https://splunk.example.com:8088",
    Token:      os.Getenv("SPLUNK_HEC_TOKEN"),
    Sourcetype: "axonops:audit",
    Index:      "audit",
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

HEC tokens authenticate via the `Authorization: Splunk <token>`
header — note the literal `Splunk` scheme (not `Bearer`). The library
rejects tokens that start with `Splunk ` or `Bearer ` (foot-gun: the
consumer pasted in the scheme prefix) and tokens containing CR/LF/NUL.

For Splunk Cloud, use the stack shortcut URL — the library expands it
to the canonical HEC endpoint:

```go
out, err := splunk.New(&splunk.Config{
    URL:   "splunkcloud://acme-prod",
    // Expands to https://http-inputs-acme-prod.splunkcloud.com:443
    Token: os.Getenv("SPLUNK_HEC_TOKEN"),
})
```

## YAML configuration

```yaml
version: 1
app_name: "my-service"
host: "${HOSTNAME}"

outputs:
  splunk_audit:
    type: splunk
    splunk:
      url: "https://splunk.example.com:8088"
      token: "${SPLUNK_HEC_TOKEN}"
      sourcetype: "axonops:audit"
      source: "audit"
      index: "audit"
      endpoint: "event"           # default — JSON envelope per event
      # endpoint: "raw"           # newline-delimited bodies; metadata in query string

      batch_size: 500             # default — events per HTTP POST
      max_batch_bytes: 819200     # default — 800 KiB (1 MB HEC cap with margin)
      max_event_bytes: 1048576    # 1 MiB — reject oversized events
      flush_interval: "2s"        # default
      timeout: "10s"              # default
      max_retries: 10             # default — HEC 5xx with exponential backoff
      gzip: true                  # default — strongly recommended (6-12× ratio)
      buffer_size: 10000          # default

      # Optional: indexer acknowledgement (compliance-grade durability)
      ack_mode: "off"             # "off" (default), "best_effort", or "required"
      # ack_poll_interval: "10s"
      # ack_resend_window: "5m"

      # Optional: copy named JSON fields into the HEC envelope's
      # `fields` object for index-time extraction.
      indexed_fields:
        - actor_id
        - resource_id

    formatter:
      type: cim_change            # CIM-compliant event shape
      vendor_product: "AxonOps:Audit"
```

A blank import registers the `splunk` output type with the YAML
loader:

```go
import _ "github.com/axonops/audit/splunk"
```

## Configuration reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | *(required)* | HEC endpoint. Two forms: `https://<host>:<port>` (Splunk Enterprise / self-managed) or `splunkcloud://<stack>` (expands to the canonical Splunk Cloud URL). HTTPS required unless `allow_insecure_http: true`. |
| `token` | string | *(required)* | HEC token. Plain opaque string — do NOT prefix with `Splunk ` or `Bearer `. CR/LF/NUL is rejected. |
| `endpoint` | string | `"event"` | `"event"` for `/services/collector/event` (JSON envelope per event, supports `indexed_fields`); `"raw"` for `/services/collector/raw` (newline-delimited bodies, metadata in query string, no envelope). |
| `sourcetype` | string | `"audit:event"` | HEC `sourcetype`. |
| `source` | string | `"audit"` | HEC `source`. |
| `index` | string | — | HEC `index`. Empty = the HEC token's default index. |
| `host` | string | `os.Hostname()` | HEC `host`. |
| `indexed_fields` | []string | — | Field names copied from the event JSON into the HEC envelope's `fields` object for index-time extraction. String values only. Ignored on `endpoint: raw`. |
| `batch_size` | int | `500` | Maximum events per HTTP POST. Range `1`–`10000`. |
| `max_batch_bytes` | int | `819200` (800 KiB) | Payload-byte threshold. Sized to leave 200 KiB headroom under HEC's 1 MB stock `max_content_length` so over-cap drops never reach the server (HTTP 413). Range `1024`–`1048576` (1 KiB–1 MiB; Splunk Cloud hard cap). |
| `max_event_bytes` | int | `1048576` (1 MiB) | Per-event cap. Events exceeding this are rejected with `audit.ErrEventTooLarge`. Range `1024`–`10485760`. |
| `flush_interval` | duration | `2s` | Maximum time between pushes. Range `100ms`–`5m`. |
| `timeout` | duration | `10s` | HTTP request timeout. Range `1s`–`5m`. |
| `max_retries` | int | `10` | Retry attempts for HEC 5xx with exponential backoff (`retry_base_delay` to `retry_max_delay`, ±`retry_jitter`). Range `0`–`100`. |
| `retry_base_delay` | duration | `500ms` | Exponential backoff base. |
| `retry_max_delay` | duration | `30s` | Exponential backoff ceiling. |
| `retry_jitter` | float | `0.2` | ±20 % jitter applied to backoff. |
| `gzip` | bool | `true` | Compress push payloads. Audit-shaped JSON typically compresses 6–12×; CPU cost is dominated by network savings. |
| `buffer_size` | int | `10000` | Internal async channel capacity. Events dropped when full. Range `100`–`1000000`. |
| `user_agent` | string | `"audit-splunk/<version>"` | User-Agent header. Must match `[A-Za-z0-9._/ -]+`. |
| `headers` | map[string]string | — | Additional headers. Reserved: `Authorization`, `X-Splunk-Request-Channel`, `Content-Type`, `Content-Encoding`, `User-Agent`. CR/LF/NUL is rejected. |
| `ack_mode` | string | `"off"` | Indexer acknowledgement: `"off"`, `"best_effort"`, or `"required"`. See [Indexer acknowledgement](#indexer-acknowledgement) below. |
| `ack_poll_interval` | duration | `10s` | Polling interval for `/services/collector/ack`. Ignored when `ack_mode: off`. |
| `ack_resend_window` | duration | `5m` | Maximum time to wait for a positive ack before resending. Ignored when `ack_mode: off`. |
| `tls.ca` | string | — | PEM CA bundle for server verification. |
| `tls.cert` | string | — | mTLS client certificate (Splunk Enterprise 10.0+ only — Splunk Cloud HEC does not support mTLS). |
| `tls.key` | string | — | mTLS client private key. Supports PKCS#8 v2 encrypted keys via `tls.key_password`. |
| `tls.key_password` | string | — | Password for encrypted `tls.key`. |
| `tls.allow_tls12` | bool | `false` | TLS 1.3 only when `false`. |
| `allow_insecure_http` | bool | `false` | Permit `http://`. MUST NOT be `true` in production. |
| `allow_private_ranges` | bool | `false` | Permit RFC 1918 / loopback. Cloud-metadata IPs remain blocked. |
| `verify_on_startup` | bool | `true` | TCP dial + TLS handshake + HEC `/health` probe at `New`. |
| `startup_verification_timeout` | duration | `5s` | Probe budget. |

## Splunk Cloud

`splunkcloud://<stack>` expands to
`https://http-inputs-<stack>.splunkcloud.com:443`. The stack name must
match `^[a-z0-9][a-z0-9-]{0,62}$` (AWS stack-naming rules — defends
against host smuggling like `acme.evil.com`). The shortcut form rejects
any path, port, query, fragment, or opaque component; use the full
`https://` form for non-standard cases.

Splunk Cloud HEC does NOT support mTLS — configuring `tls.cert`,
`tls.key`, or `tls.ca` with a `splunkcloud://` URL is rejected at
config validation. For mTLS, target a self-managed HTTPS proxy that
terminates the client certificate and forwards to Splunk Cloud.

## Indexer acknowledgement

HEC indexer acknowledgement is the durability gap between "HEC
accepted" (HTTP 200) and "the indexer replicated the event at the
cluster's replication factor". Three modes:

| Mode          | Channel header | Polling | Buffer gating          | Use when                                |
|---------------|----------------|---------|------------------------|-----------------------------------------|
| `off`         | none           | no      | n/a                    | Standard observability — HTTP 200 is the only durability signal. Lowest overhead. |
| `best_effort` | yes            | yes     | NOT gated              | You want delivery telemetry (`ack_*` metrics) without producer back-pressure. |
| `required`    | yes            | yes     | gated until positive   | Compliance-grade at-least-once delivery. Events stay in the in-flight buffer until ack returns positive; on `ack_resend_window` timeout the events re-send. |

The HEC token MUST have ACK enabled in Splunk for `best_effort` /
`required`. With `ack_mode: required`, when the in-flight buffer
reaches `buffer_size` new batches drop with reason
`ack_buffer_full` rather than stalling — `Write` remains
non-blocking by contract.

## CIM Change formatter

Pair the splunk output with `formatter.type: cim_change` (and
`vendor_product:`) to emit events in Splunk's CIM Change data-model
shape, with the reference Splunk Technology Add-on (`deploy/splunk-ta-axonops-audit/`)
auto-extracting every CIM Change field and tagging events
`tag=change`. The formatter is wired at the auditor level —
`splunk.Output` itself is formatter-agnostic.

## See also

- [Full output reference][docs] — HEC error codes, retry semantics,
  ACK protocol, CIM Change formatter
- [Worked example][example] — `outputs.yaml` + `main.go` pushing to a
  local Splunk container with the CIM Change formatter
- [Splunk TA reference][docs-ta] — the bundled add-on for index-time
  extraction
- [TLS policy](../docs/output-configuration.md#tls) — TLS 1.3-only
  defaults, TLS 1.2 fallback
- Related outputs:
  [`webhook`](../webhook/) (generic HTTPS — for non-Splunk SIEMs),
  [`syslog`](../syslog/) (RFC 5424 — for Splunk via syslog forwarder),
  [`loki`](../loki/) (Grafana Loki),
  [`file`](../file/) (local file with rotation)

[godoc]: https://pkg.go.dev/github.com/axonops/audit/splunk
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/splunk.svg
[audit-output]: https://pkg.go.dev/github.com/axonops/audit#Output
[docs]: ../docs/splunk-output.md
[docs-ta]: ../docs/splunk-ta.md
[example]: ../examples/09-splunk-output/
