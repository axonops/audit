# syslog — RFC 5424 syslog output (TCP, UDP, TLS, mTLS)

[![Go Reference][godoc-badge]][godoc]

Sends audit events to a syslog receiver as
[RFC 5424][rfc5424] structured messages over TCP, UDP, or TCP+TLS
(including mTLS). Implements the [`audit.Output`][audit-output]
interface. Built on the AxonOps fork of `gravwell/srslog`.

> **Module path**: `github.com/axonops/audit/syslog`
> **Status**: pre-release (v0.x)
> **Documentation**: [syslog-output.md][docs] · [examples/06-syslog-output][example]

## Why

Syslog is the lingua franca of SIEM ingestion. Splunk, ArcSight,
QRadar, Elastic, Graylog, LogRhythm, and every cloud-vendor security
service accept it natively, and most production environments already
run an rsyslog or syslog-ng collector that can fan events out to
multiple downstream consumers without you deploying anything new.
PCI DSS, SOC 2, and HIPAA commonly require centralised audit
collection via syslog.

Use syslog when your SIEM speaks it (every SIEM does), when
infrastructure constraints rule out HTTP, or when you want the
collector — not the application — to own delivery reliability and
fan-out. Use [webhook](../webhook/) when the destination speaks HTTPS
but not syslog (modern SaaS SIEMs); use [`splunk`](../splunk/) for
direct Splunk HEC delivery without an intermediate forwarder.

## Install

```bash
go get github.com/axonops/audit/syslog
```

Requires Go 1.26+. See the [main README](../README.md) for transitive
dependencies.

## Quick start

```go
import (
    "github.com/axonops/audit"
    "github.com/axonops/audit/syslog"
)

out, err := syslog.New(&syslog.Config{
    Network: "tcp",
    Address: "syslog.internal:514",
    AppName: "myapp",
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

By default the receiver MUST be reachable at startup — `New` dials the
syslog server (and completes the TLS handshake on `tcp+tls`) before
returning, so misconfigured destinations fail fast. Disable the probe
via the `Config.DisableStartupVerification` Go field (or `verify_on_startup: false`
in YAML — note the inversion: the YAML key is the positive form) for
sidecar deployments where the collector may not be ready when the
application boots; in that mode the writeLoop reconnects transparently
as the first events arrive.

## YAML configuration

Plain TCP (the simplest production setup, when the syslog collector is
on the same host or trusted network):

```yaml
version: 1
app_name: "my-service"
host: "${HOSTNAME}"

outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp"               # "tcp" (default), "udp", or "tcp+tls"
      address: "syslog.internal:514"
      app_name: "myapp"            # RFC 5424 APP-NAME
      facility: "local0"           # default
      max_retries: 10              # default — reconnect attempts
      batch_size: 100              # default — events per flush
      flush_interval: "5s"         # default
```

TCP+TLS with mTLS (production-grade SIEM ingest):

```yaml
outputs:
  siem:
    type: syslog
    syslog:
      network: "tcp+tls"
      address: "syslog.example.com:6514"
      app_name: "myapp"
      facility: "local0"
      tls:
        ca:   "/etc/audit/ca.pem"
        cert: "/etc/audit/client-cert.pem"
        key:  "/etc/audit/client-key.pem"
        # key_password: "${TLS_KEY_PASSWORD}"   # PKCS#8 v2 encrypted keys
        # allow_tls12: false                     # default — TLS 1.3 only
    formatter:
      type: cef                    # CEF is the SIEM-native format
      vendor: "MyCompany"
      product: "MyApp"
      version: "1.0"
```

A blank import registers the `syslog` output type with the YAML
loader:

```go
import _ "github.com/axonops/audit/syslog"
```

## Configuration reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `address` | string | *(required)* | Receiver `host:port`. |
| `network` | string | `"tcp"` | `"tcp"`, `"udp"`, or `"tcp+tls"`. UDP may silently truncate messages over the network MTU (~2 KiB) — use TCP or TCP+TLS for reliable delivery of large audit events. |
| `app_name` | string | `"audit"` | RFC 5424 APP-NAME field. Cascades from the top-level auditor `app_name` when omitted. |
| `facility` | string | `"local0"` | Syslog facility. One of: `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0`–`local7`. Unknown values are rejected. |
| `hostname` | string | `os.Hostname()` | RFC 5424 HOSTNAME field. Must be printable ASCII (bytes 33–126), max 255 bytes. |
| `tls.ca` | string | — | Path to a PEM CA bundle used to verify the server certificate on `tcp+tls`. |
| `tls.cert` | string | — | Path to the client certificate for mTLS. Must be set together with `tls.key`. |
| `tls.key` | string | — | Path to the client private key for mTLS. PKCS#8 v2 encrypted keys are supported via `tls.key_password`. PKCS#1 DEK-Info legacy keys are refused. |
| `tls.key_password` | string | — | Password for an encrypted `tls.key`. Use a secret reference (`ref+openbao://…`, env var) in production. |
| `tls.allow_tls12` | bool | `false` | When `false`, only TLS 1.3 is accepted. Set `true` to permit TLS 1.2 fallback. |
| `tls_handshake_timeout` | duration | `10s` | TCP dial + TLS handshake budget per connection attempt (`tcp+tls` only). Range `100ms`–`60s`. |
| `max_retries` | int | `10` | Consecutive reconnect attempts before giving up. Max `20`. |
| `buffer_size` | int | `10000` | Internal async channel capacity. Events dropped when full; `OutputMetrics.RecordDrop` is called. Max `100000`. |
| `batch_size` | int | `100` | Events accumulated before flushing. Set `1` to flush every event immediately. Max `10000`. |
| `flush_interval` | duration | `5s` | Maximum time between flushes regardless of batch fill. Range `1ms`–`1h`. |
| `max_batch_bytes` | int | `1048576` (1 MiB) | Payload-byte threshold that flushes the batch independently of `batch_size`. A single event over this size is flushed alone; it is never dropped. Range `1024`–`10485760` (1 KiB–10 MiB). |
| `max_event_bytes` | int | `1048576` (1 MiB) | Per-event size cap. Events exceeding this are rejected with `audit.ErrEventTooLarge`. Defends against consumer-controlled memory pressure. Range `1024`–`10485760` (1 KiB–10 MiB). |
| `verify_on_startup` | bool | `true` | When `true`, `New` performs a TCP dial — and on `tcp+tls` a TLS handshake — before returning. Set `false` for sidecar startup ordering. |
| `startup_verification_timeout` | duration | `5s` | Budget for the construction-time connectivity probe. Ignored when `verify_on_startup: false`. |

## Reconnection

TCP and TLS connections re-establish automatically on write failure
with exponential backoff (100 ms base, capped at 30 s), up to
`max_retries` attempts. UDP is connectionless — there is no reconnect,
but oversized datagrams may be silently dropped by the network.

A per-output metrics implementation MAY also implement
`syslog.ReconnectRecorder`:

```go
type ReconnectRecorder interface {
    RecordReconnect(success bool, attempt int)
}
```

If present, `RecordReconnect` is called on every reconnect attempt.
Discovery is by structural typing — no explicit registration.

## Severity mapping

Audit severity (0–10) maps to syslog severity as follows:

| Audit | Syslog                | Notes                                  |
|------:|-----------------------|----------------------------------------|
| 10    | `LOG_CRIT` (2)        | Critical security events               |
| 8–9   | `LOG_ERR` (3)         | High-severity events                   |
| 6–7   | `LOG_WARNING` (4)     | Medium-severity events                 |
| 4–5   | `LOG_NOTICE` (5)      | Normal operational events              |
| 1–3   | `LOG_INFO` (6)        | Low-severity informational events      |
| 0     | `LOG_DEBUG` (7)       | Debug / trace                          |

`LOG_EMERG` (0) and `LOG_ALERT` (1) are intentionally never emitted —
they trigger console broadcasts and pager alerts on many syslog
receivers, which an audit library has no business doing.

## See also

- [Full output reference][docs] — RFC 5424 message structure, TLS
  configuration, facility selection, CEF pairing, troubleshooting
- [Worked example][example] — `outputs.yaml` + `main.go` with an
  embedded TCP receiver so the example runs without external services
- [CEF format reference](../docs/cef-format.md) — the SIEM-native
  formatter typically paired with syslog
- [TLS policy](../docs/output-configuration.md#tls) — TLS 1.3-only
  defaults, TLS 1.2 fallback, weak-cipher policy
- Related outputs:
  [`file`](../file/) (local file with rotation),
  [`webhook`](../webhook/) (HTTPS push for SaaS SIEMs),
  [`splunk`](../splunk/) (direct Splunk HEC),
  [`loki`](../loki/) (Grafana Loki for LogQL)

[godoc]: https://pkg.go.dev/github.com/axonops/audit/syslog
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/syslog.svg
[audit-output]: https://pkg.go.dev/github.com/axonops/audit#Output
[docs]: ../docs/syslog-output.md
[example]: ../examples/06-syslog-output/
[rfc5424]: https://datatracker.ietf.org/doc/html/rfc5424
