[← Back to Output Types](outputs.md)

# Splunk Output — Detailed Reference

The Splunk output sends audit events to Splunk via the
[HTTP Event Collector (HEC)](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
`/event` or `/raw` endpoints. Events are batched, gzipped by default,
delivered with exponential backoff retry, and optionally
acknowledged via Splunk's
[indexer acknowledgement](https://docs.splunk.com/Documentation/Splunk/latest/Data/AboutHECIDXAck)
protocol for end-to-end durability.

- [Why Splunk HEC for Audit?](#why-splunk-hec-for-audit)
- [Quick Start](#quick-start)
- [URL Forms](#url-forms)
- [Authentication](#authentication)
- [Endpoint Selection: `/event` vs `/raw`](#endpoint-selection-event-vs-raw)
- [Formatter Choice: `json` vs `cim_change`](#formatter-choice-json-vs-cim_change)
- [Indexer Acknowledgement](#indexer-acknowledgement)
- [Splunk Cloud Specifics](#splunk-cloud-specifics)
- [Complete Configuration Reference](#complete-configuration-reference)
- [The Reference TA](#the-reference-ta)
- [Troubleshooting](#troubleshooting)

---

## Why Splunk HEC for Audit?

The generic webhook output works against Splunk HEC but doesn't
honour the Splunk-specific conventions. The dedicated Splunk output
adds:

- **Non-standard auth** (`Authorization: Splunk <token>` — not
  `Bearer`).
- **Per-event envelope wrapping** (`{"event": ..., "time": ...,
  "sourcetype": ..., "host": ..., "source": ...}`) for the `/event`
  endpoint.
- **The full 28-entry HEC error code table** — every documented
  HEC response code (success / retry / drop / stop / capacity-warn
  / ack-disabled) is classified explicitly so retries don't loop
  on permanent failures.
- **Indexer acknowledgement** with three modes (off / best-effort /
  required) covering best-effort dashboards through compliance-grade
  guaranteed delivery.
- **CIM Change formatter** (`cim_change`) for events that need to
  populate the Splunk Common Information Model out of the box.
- **Splunk Cloud URL shortcut** (`splunkcloud://acme-prod`) that
  expands to the canonical
  `https://http-inputs-acme-prod.splunkcloud.com:443` form.

If you need plain text/JSON delivery to a generic Splunk HEC and
don't care about ACK or CIM, the webhook output works. Use the
Splunk output when you need any of the features above.

---

## Quick Start

```yaml
outputs:
  splunk_compliance:
    type: splunk
    url: https://splunk.example.com:8088
    token: !secret splunk_hec_token
    sourcetype: axonops:audit
    formatter:
      type: cim_change
```

Programmatically:

```go
import (
    "github.com/axonops/audit"
    "github.com/axonops/audit/splunk"
)

out, err := splunk.New(&splunk.Config{
    URL:        "https://splunk.example.com:8088",
    Token:      os.Getenv("SPLUNK_HEC_TOKEN"),
    Sourcetype: "axonops:audit",
})
if err != nil { /* handle */ }
defer out.Close()

auditor, err := audit.New(taxonomy, audit.WithOutput(out))
```

---

## URL Forms

The output accepts two URL forms:

| Form | Example | Notes |
|------|---------|-------|
| Full HTTPS | `https://splunk.example.com:8088` | Splunk Enterprise / self-managed |
| Splunk Cloud shortcut | `splunkcloud://acme-prod` | Expands to `https://http-inputs-acme-prod.splunkcloud.com:443` |

The Splunk Cloud shortcut validates the stack name against
`^[a-z0-9][a-z0-9-]{0,62}$` and rejects custom TLS material
(`TLSCert`/`TLSKey`/`TLSCA`) — Splunk Cloud HEC presents a
public-CA-signed cert and silently dropping operator-supplied TLS
settings would be a security surprise.

`http://` URLs are rejected unless `allow_insecure_http: true` is
set. Use the insecure form only in development.

---

## Authentication

HEC uses a non-standard auth scheme — the library sets
`Authorization: Splunk <token>` automatically. Don't include the
`Splunk ` or `Bearer ` prefix in your token value; the library
rejects token configs with these prefixes to prevent the
double-prefix footgun.

Provision a token via Splunk Web → **Settings** → **Data inputs**
→ **HTTP Event Collector** → **New Token**. Required settings:

- **Source type:** `axonops:audit` (or whatever you've configured
  in the YAML).
- **Index:** any index your audit retention policy targets.
- **Indexer Acknowledgement:** enable if you'll use
  `ack_mode: best_effort` or `ack_mode: required`.

---

## Endpoint Selection: `/event` vs `/raw`

| Endpoint | When to use |
|---|---|
| `endpoint: event` (default) | JSON events with per-event metadata (sourcetype, host, time). Pairs with the `cim_change` formatter for CIM compliance. |
| `endpoint: raw` | Pre-formatted text events (e.g., NDJSON, CEF, syslog). Splunk extracts metadata from the request query string, not the body. |

Most consumers want `/event`. Use `/raw` when integrating with a
pipeline that already speaks a Splunk-native format (CEF for
ArcSight, syslog for legacy).

---

## Formatter Choice: `json` vs `cim_change`

| Formatter | Output | When to use |
|---|---|---|
| `json` (default) | Audit fields verbatim — `event_type`, `actor_id`, `outcome`, etc. | Quickest to set up; consumers query by the library's field names. |
| `cim_change` | CIM Change data-model field names — `action`, `user_id`, `object`, `status`, `vendor_product`. | Required for Splunk Enterprise Security dashboards and any Splunk content pack that keys off CIM. |

The `cim_change` formatter:

- Maps `event_type → action`, `event_category → change_type`,
  `actor → user/user_id/user_name`,
  `target → object/object_id/object_category/object_path/object_attrs`,
  `outcome → status (collapsed) + outcome (preserved)`,
  `source_ip → src`, `app_name → vendor_product`, `host → dvc + host`.
- Collapses the audit `outcome` enum to CIM's binary
  `success`/`failure` for the `status` field, AND preserves the
  original `outcome` value alongside so consumers can recover the
  granular semantic.
- Emits the audit `severity` integer as `severity_id` (a CIM
  extension; avoids collision with consumer-supplied string
  `severity` fields).

Pair `cim_change` with the [reference TA](#the-reference-ta) for
zero-config CIM tagging.

---

## Indexer Acknowledgement

HEC's indexer acknowledgement protocol confirms when an event has
been **indexed** (not just received). Three modes:

| Mode | Buffer gating | Resend | When to use |
|---|---|---|---|
| `off` (default) | none | none | Throughput-first; HTTP 200 is the only durability signal. |
| `best_effort` | none | none | Best-effort observability via ack metrics; producer never blocks on ack. |
| `required` | in-flight buffer bounded by `buffer_size` | yes, on `ack_resend_window` expiry | Compliance-grade durability; events stay in-flight until ack returns positive. |

Required mode keeps events in an in-flight buffer until ack
confirms; if the buffer fills (no acks coming back), new events
drop with metric `reason=ack_buffer_full` — the producer is
**never blocked**.

```yaml
outputs:
  splunk_compliance:
    type: splunk
    url: https://splunk.example.com:8088
    token: !secret splunk_hec_token
    ack_mode: required
    ack_poll_interval: 5s
    ack_resend_window: 60s
```

The token MUST have ACK enabled on its channel; the library
feature-detects at startup and refuses to launch if ACK is disabled
(returns `splunk.ErrAckDisabled`).

---

## Splunk Cloud Specifics

- **No mTLS.** Splunk Cloud HEC presents a public-CA-signed cert.
  Setting `tls_cert`/`tls_key`/`tls_ca` with a `splunkcloud://`
  URL is rejected at config validation.
- **Token visibility.** HEC tokens for Splunk Cloud must be created
  in the Splunk Cloud Web UI (not via REST API) for some
  deployment topologies.
- **App installation.** Custom TAs (including the
  [reference TA](#the-reference-ta)) may require a Splunk Cloud
  support ticket to install if they haven't been published to
  Splunkbase.

---

## Complete Configuration Reference

See [`splunk/config.go`](../splunk/config.go) for the
exhaustive field documentation. The most-frequently-used fields:

| YAML key | Default | Notes |
|---|---|---|
| `url` | required | HTTPS URL or `splunkcloud://<stack>` |
| `token` | required | HEC token (no scheme prefix) |
| `endpoint` | `event` | `event` or `raw` |
| `sourcetype` | `axonops:audit` | Splunk sourcetype label |
| `source` | empty | Splunk source label (e.g., `axonops:audit:prod`) |
| `index` | empty | Splunk index (token's default if omitted) |
| `host` | empty | Splunk host label |
| `batch_size` | `100` | Events per batch |
| `max_batch_bytes` | `819200` (800 KiB) | Pre-flush cap; oversize batches drop client-side |
| `max_event_bytes` | `1048576` (1 MiB) | Per-event cap; oversize events drop at Write |
| `flush_interval` | `5s` | Trigger flush on this timer regardless of batch fill |
| `gzip` | `true` | Compress request bodies |
| `timeout` | `30s` | Per-request HTTP timeout |
| `max_retries` | `5` | Retries on actionRetry HEC codes (9, 8, 18-20, 23, 26) |
| `retry_base_delay` | `500ms` | Exponential backoff base |
| `retry_max_delay` | `30s` | Backoff cap |
| `buffer_size` | `10000` | Internal async buffer + in-flight ack cap for `required` mode |
| `ack_mode` | `off` | `off` / `best_effort` / `required` |
| `ack_poll_interval` | `5s` | How often to poll `/services/collector/ack` |
| `ack_resend_window` | `60s` | Required-mode resend timer |
| `tls_policy.allow_tls12` | `false` | Required for some legacy Splunk Enterprise builds |
| `verify_on_startup` | `true` | Run `/services/collector/health` probe at construction |

---

## The Reference TA

The library ships a reference Splunk Technology Add-on at
[`deploy/splunk-ta-axonops-audit/`](../deploy/splunk-ta-axonops-audit/).
Installing it:

1. Pair with `formatter: { type: cim_change }` in your output config.
2. Copy the TA into `$SPLUNK_HOME/etc/apps/TA-axonops-audit/`
   (Splunk Enterprise) or install via Splunk Web (Splunk Cloud).
3. Restart Splunk.

The TA provides:

- `KV_MODE = json` for the `axonops:audit` sourcetype — every CIM
  field is searchable at search time (works for both HEC direct
  ingest and forwarder ingest).
- `change` tag on every audit event (CIM Change data model).
- `authentication` tag on `security:*` events (CIM Authentication
  data model).
- `vendor_product = "AxonOps:Audit"` as a per-TA EVAL constant.
- A starter dashboard at `Audit Events`.

For consumer-specific taxonomies, regenerate the TA via
[`docs/splunk-ta.md`](splunk-ta.md).

---

## Testing this output

The splunk output ships with three test layers — pick the one that
matches the assertion you need.

### Unit tests (no infrastructure)

```bash
make test-splunk
```

Cover the in-memory contract — config validation, envelope
wrapping, HEC response-code action dispatch (the `classify`
function), ACK state machine, channel GUID generation, retry
backoff. Run on every PR; no Docker needed.

| Test file | What it pins |
|---|---|
| `config_test.go` | Config defaults, validation rules, env-var resolution. |
| `envelope_test.go` | HEC `/event` and `/raw` wire envelope shapes. |
| `errors_test.go` | Sentinel errors, redaction, HEC `code` → action mapping. |
| `ack_test.go` | ACK tracker state machine, resend window, channel GUID. |
| `http_test.go` + `http_failures_test.go` | HTTP transport, response classify, retry/backoff. |
| `splunk_test.go` | Public-API `New`/`Write`/`Close` contract. |
| `register_test.go` | YAML output-factory registration. |
| `property_test.go` | Rapid-driven property checks on envelope + classify. |
| `redact_test.go` | Token redaction in `String`/`GoString`/`Format`. |
| `bench_test.go` | Hot-path allocation + throughput benchmarks. |

### Integration tests (real Splunk container)

```bash
make test-infra-splunk-up
make test-integration-splunk
make test-infra-splunk-down
```

Drive the output end-to-end against a real Splunk Enterprise
container (the pinned image tag lives in
[`tests/bdd/docker-compose.splunk.yml`](../tests/bdd/docker-compose.splunk.yml)).
The full suite covers:

| Test file | What it pins |
|---|---|
| `splunk_test.go` | Wire-format envelope (`/event` + `/raw`), gzip, batching, search round-trip. |
| `splunk_cim_test.go` | `CIMChangeFormatter` mapping: `actor_id → user_id`, `event_type → action`, `outcome → status` collapse, gzip preservation, `_time` parsing. |
| `splunk_ack_test.go` | ACK state machine including the deterministic resend-on-timeout path via an in-process HTTP reverse-proxy. |
| `splunk_ta_install_test.go` | Reference TA install end-to-end: eventtype loading, `KV_MODE=json` extraction without `spath`, `EVAL-vendor_product` override, every eventtype tagged `change`, `tag=authentication` only on security-category events. |
| `splunk_security_test.go` | HMAC integrity round-trip via `audit.VerifyHMAC`; sensitivity-label PII stripping (substring + JSON tree walk + Splunk-wide value search); HMAC-over-stripped-payload combined-config invariant. |
| `splunk_fanout_test.go` | Auditor fan-out: file + splunk delivery, dead-splunk isolation (file still gets all events), per-output formatters (JSON to file, CIM to splunk). |
| `splunk_metrics_test.go` | `audit.OutputMetrics` integration: flush accuracy, buffer-full drops via blocking server, HEC code 24 counts as flush (not drop), oversize event drops at Write. |

The integration suite skips on `arm64` because Splunk does not
publish an arm64 container image. ACK-mode tests that require the
container token to have indexer-acknowledgement enabled skip
cleanly when the test container's HEC token does not — the
deterministic ACK resend test in `splunk_ack_test.go` runs
unconditionally because it synthesises ackIds via an in-process
proxy.

### BDD scenarios (Gherkin)

```bash
make test-bdd-splunk        # @docker scenarios, against real container
make test-bdd-splunk-stub   # @stub scenarios, in-process HEC stub
```

`tests/bdd/features/splunk_output.feature` documents every
operator-visible behaviour as a Gherkin scenario. Happy-path
scenarios (`@docker`) drive the real container; HEC error-code
scenarios (`@stub`) drive an in-process stub because real Splunk
does not produce codes 4/7/9/24/413 on demand.

The `@appinspect` scenario runs `splunk-appinspect --mode precert`
against the generated reference TA; it is gated by the
`splunk-appinspect` Python tool being on `PATH` and runs in the
`splunk-ta-appinspect` CI job.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `ErrConfigInvalid: URL scheme http is rejected unless AllowInsecureHTTP=true` | `http://` URL configured | Use `https://`, or set `allow_insecure_http: true` for development. |
| `ErrConfigInvalid: splunkcloud:// does not support custom TLS material` | `splunkcloud://` + `tls_cert`/`tls_key`/`tls_ca` set | Remove the TLS material — Splunk Cloud uses public-CA TLS. |
| `ErrConfigInvalid: Token must not start with "Splunk "` | Token includes the auth-scheme prefix | Strip the prefix from your token value; the library adds it. |
| `ErrHealthCheckFailed` | `/services/collector/health` returned non-200 at startup | Verify the HEC port is reachable, the token is valid, and the SSL mode matches (`SPLUNK_HEC_SSL` server setting). |
| `ErrAckDisabled` | `ack_mode != off` but the token's channel has ACK disabled | Enable ACK on the HEC token in Splunk Web. |
| `ErrCryptoRandFailed` | `crypto/rand` unavailable (extremely rare) | Filed only on broken kernels; investigate before restarting. |
| Drop metric increments with `reason=ack_buffer_full` | `ack_mode: required` and acks aren't returning positive fast enough | Increase `buffer_size` or investigate ack-poll latency. |
| Drop metric increments with `reason=oversize` | Single event exceeds `max_event_bytes` | Truncate or downsample upstream; the cap is enforced at Write time to prevent unbounded memory. |

See [`docs/error-reference.md`](error-reference.md) for the full
list of audit library sentinel errors.

---

## Related

- [Splunk TA Generator](splunk-ta.md) — produce a custom TA from
  your own taxonomy.
- [Output Types](outputs.md) — overview of all output types.
- [CIM Change formatter](json-format.md#cim-change-formatter) —
  formatter contract details.
