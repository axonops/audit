# loki — Grafana Loki output (LogQL push API)

[![Go Reference][godoc-badge]][godoc]

Pushes audit events to a Grafana Loki instance via the HTTP push API
(`POST /loki/api/v1/push`) with configurable stream labels, gzip
compression, multi-tenant support, and TLS. Implements the
[`audit.Output`][audit-output] interface.

> **Module path**: `github.com/axonops/audit/loki`
> **Status**: pre-release (v0.x)
> **Documentation**: [loki-output.md][docs] · [examples/08-loki-output][example]

## Why

Loki is the de-facto open-source log store for Grafana-native
observability stacks. Pushing audit events to Loki gives you LogQL —
`{event_type="auth_failure"} | json | actor_id="alice"` — alongside
your application logs and metrics, in one query language, in one UI.
You also get Grafana alerting on audit patterns without an additional
SIEM, multi-tenant isolation via `X-Scope-OrgID`, and Loki's stream
label model for cheap categorical filtering before LogQL parses the
JSON body.

Use Loki when you already run Grafana for metrics and logs and want
audit events in the same surface. Use [`splunk`](../splunk/) for
direct Splunk HEC delivery, [`syslog`](../syslog/) when the
destination speaks RFC 5424, or [`webhook`](../webhook/) for generic
HTTP sinks.

## Install

```bash
go get github.com/axonops/audit/loki
```

Requires Go 1.26+. See the [main README](../README.md) for transitive
dependencies.

## Quick start

```go
import (
    "github.com/axonops/audit"
    "github.com/axonops/audit/loki"
)

out, err := loki.New(&loki.Config{
    URL:      "https://loki.example.com/loki/api/v1/push",
    TenantID: "acme-corp",
    Labels: loki.LabelConfig{
        Static: map[string]string{
            "job":         "audit",
            "environment": "production",
        },
    },
    Gzip: true,
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

Loki is JSON-only — the formatter for a Loki output cannot be changed
to CEF or any other format, because LogQL relies on `| json` to parse
the line body. Custom user-defined fields stay in the JSON body and
remain queryable via `| json | field="value"`; the label set is
deliberately scoped to a small, low-cardinality default to stay
within Loki's recommended per-tenant stream ceiling.

## YAML configuration

```yaml
version: 1
app_name: "my-service"
host: "${HOSTNAME}"

outputs:
  loki_audit:
    type: loki
    loki:
      url: "https://loki.example.com/loki/api/v1/push"
      tenant_id: "${LOKI_TENANT}"     # X-Scope-OrgID for multi-tenant Loki
      batch_size: 100                 # default — events per push
      max_batch_bytes: 1048576        # 1 MiB — flush at this payload size
      max_event_bytes: 1048576        # 1 MiB — reject oversized events
      flush_interval: "5s"            # default
      timeout: "10s"                  # default
      max_retries: 3                  # default — retry on 429/5xx
      gzip: true                      # YAML default true; Go zero-value false
      buffer_size: 10000              # default — events dropped when full
      labels:
        static:
          job: "audit"
          environment: "production"
        dynamic:
          pid: false                  # exclude PID (high cardinality)
      # basic_auth:
      #   username: "loki-writer"
      #   password: "${LOKI_PASSWORD}"
      # bearer_token: "${LOKI_TOKEN}"
      tls:
        ca:   "/etc/audit/ca.pem"
        # cert: "/etc/audit/client-cert.pem"   # mTLS
        # key:  "/etc/audit/client-key.pem"
        # key_password: "${TLS_KEY_PASSWORD}"
        # allow_tls12: false                    # default — TLS 1.3 only
```

A blank import registers the `loki` output type with the YAML loader:

```go
import _ "github.com/axonops/audit/loki"
```

## Configuration reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | *(required)* | Full push endpoint including path, e.g. `https://loki:3100/loki/api/v1/push`. HTTPS required unless `allow_insecure_http: true`. URLs with embedded credentials are rejected — use `basic_auth`. |
| `tenant_id` | string | — | `X-Scope-OrgID` header for multi-tenant Loki. |
| `basic_auth.username` | string | — | HTTP basic auth username. Required when `basic_auth` is set. Mutually exclusive with `bearer_token`. |
| `basic_auth.password` | string | — | HTTP basic auth password. Use a secret reference in production. |
| `bearer_token` | string | — | Sets `Authorization: Bearer <token>`. Mutually exclusive with `basic_auth`. |
| `headers` | map[string]string | — | Additional HTTP headers. The library reserves `Authorization`, `X-Scope-OrgID`, `Content-Type`, `Content-Encoding`, and `Host` — use the dedicated config fields for those. CRLF in either name or value is rejected. |
| `labels.static` | map[string]string | — | Constant labels applied to every event. Keys must match `[a-zA-Z_][a-zA-Z0-9_]*` (Loki requirement). Values must be non-empty and free of control characters. |
| `labels.dynamic.app_name` | bool | included | Drop the per-event `app_name` label when `false`. |
| `labels.dynamic.host` | bool | included | Drop the per-event `host` label when `false`. Significant cardinality in fleet deployments — consider excluding. |
| `labels.dynamic.timezone` | bool | included | Drop the `timezone` label when `false`. Cardinality typically 1. |
| `labels.dynamic.pid` | bool | included | Drop the `pid` label when `false`. **Strongly recommended in production** — every process restart creates a new label value. |
| `labels.dynamic.event_type` | bool | included | Drop the `event_type` label when `false`. |
| `labels.dynamic.event_category` | bool | included | Drop the `event_category` label when `false`. |
| `labels.dynamic.severity` | bool | included | Drop the `severity` label when `false`. |
| `tls.ca` | string | — | Path to a PEM CA bundle. Falls back to the system root pool when empty. |
| `tls.cert` | string | — | mTLS client certificate. Set with `tls.key`. |
| `tls.key` | string | — | mTLS client private key. Supports PKCS#8 v2 encrypted keys via `tls.key_password`. |
| `tls.key_password` | string | — | Password for encrypted `tls.key`. |
| `tls.allow_tls12` | bool | `false` | TLS 1.3 only when `false`. |
| `batch_size` | int | `100` | Events per push request. Range `1`–`10000`. |
| `max_batch_bytes` | int | `1048576` (1 MiB) | Maximum uncompressed payload per push. Range `1024`–`10485760` (1 KiB–10 MiB). |
| `max_event_bytes` | int | `1048576` (1 MiB) | Per-event cap. Events exceeding this are rejected with `audit.ErrEventTooLarge`. Range `1024`–`10485760`. |
| `flush_interval` | duration | `5s` | Maximum time between pushes. Range `100ms`–`5m`. |
| `timeout` | duration | `10s` | HTTP request timeout. Range `1s`–`5m`. The transport-level `ResponseHeaderTimeout` is derived as `max(timeout/2, 1s)`. |
| `max_retries` | int | `3` | Retry attempts for 429/5xx. Range `1`–`20`. |
| `buffer_size` | int | `10000` | Internal async channel capacity. Events dropped when full. Range `100`–`1000000`. |
| `gzip` | bool | YAML `true` / Go `false` | Gzip-compress push requests (the only encoding Loki accepts). Programmatic constructors must set this explicitly — the Go zero value is `false`. |
| `allow_insecure_http` | bool | `false` | Permit `http://`. MUST NOT be `true` in production. |
| `allow_private_ranges` | bool | `false` | Permit RFC 1918 / loopback. Intended for testing. |
| `verify_on_startup` | bool | `true` | When `true`, `New` performs a TCP dial and TLS handshake before returning. |
| `startup_verification_timeout` | duration | `5s` | Probe budget. Ignored when `verify_on_startup: false`. |

## Stream labels and cardinality

Each unique combination of label values is a separate Loki stream.
Loki's recommended ceiling is around 100 k active streams per tenant —
once you blow past that, ingestion latency degrades sharply and the
tenant can be rate-limited. The dynamic label set is chosen to stay
inside that ceiling for typical multi-host, multi-app deployments:

| Label             | Cardinality driver                            | Default | Recommendation                                  |
|-------------------|-----------------------------------------------|---------|-------------------------------------------------|
| `app_name`        | distinct applications per tenant              | on      | usually low (<20) — safe to keep                |
| `host`            | distinct hosts                                | on      | fleet deployments: consider excluding           |
| `timezone`        | distinct timezones                            | on      | typically 1 — safe to keep                      |
| `pid`             | every process restart creates a new value     | on      | **exclude in production**                       |
| `event_type`      | size of the taxonomy                          | on      | usually 10–200 — safe to keep                   |
| `event_category`  | distinct categories                           | on      | typically 5–20 — safe to keep                   |
| `severity`        | at most 11 (0–10)                             | on      | always safe to keep                             |

User-defined fields are NEVER labels — they stay in the JSON body and
are queryable through `| json | field_name="value"`.

## Delivery model

Events batch in memory and push when any of these thresholds is
reached: `batch_size` events queued, accumulated payload reaches
`max_batch_bytes`, or `flush_interval` elapses. `Close` flushes
remaining events. Retries fire on 429 (honouring `Retry-After`) and
5xx with exponential backoff.

Delivery is **at-least-once** — duplicate delivery is possible if the
server accepts the payload but the acknowledgement is lost.

## See also

- [Full output reference][docs] — push API details, label cardinality,
  multi-tenancy, gzip
- [Worked example][example] — `outputs.yaml` + `main.go` that pushes
  to a local Loki container
- [TLS policy](../docs/output-configuration.md#tls) — TLS 1.3-only
  defaults, TLS 1.2 fallback
- Related outputs:
  [`splunk`](../splunk/) (Splunk HEC),
  [`syslog`](../syslog/) (RFC 5424),
  [`webhook`](../webhook/) (generic HTTPS),
  [`file`](../file/) (local file with rotation)

[godoc]: https://pkg.go.dev/github.com/axonops/audit/loki
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/loki.svg
[audit-output]: https://pkg.go.dev/github.com/axonops/audit#Output
[docs]: ../docs/loki-output.md
[example]: ../examples/08-loki-output/
