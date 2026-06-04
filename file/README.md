# file — local audit-log file output with rotation

[![Go Reference][godoc-badge]][godoc]

Writes serialised audit events to a local file with size-based
rotation, count- and age-based backup retention, and optional
gzip compression of rotated files. Implements the
[`audit.Output`][audit-output] interface.

> **Module path**: `github.com/axonops/audit/file`
> **Status**: pre-release (v0.x)
> **Documentation**: [file-output.md][docs] · [examples/03-file-output][example]

## Why

A local file is the simplest durable destination for an audit trail.
Standard Unix tools (`grep`, `jq`, `tail -f`) work on it directly,
rotated backups can be shipped to S3 or tape for compliance retention,
and there are no network dependencies — no SIEM outage can drop events
on the floor. Pair with HMAC integrity (configured at the output level
in `outputs.yaml`) for tamper-evident logs that satisfy SOX, HIPAA,
and PCI DSS file-based audit-trail requirements.

Use file output when you want a complete unfiltered audit trail on
local disk, and ship the file (or its rotated backups) into a SIEM
separately. Use webhook, syslog, Loki, or Splunk directly when you
want the event stream pushed into a remote system without an
intermediate file.

## Install

```bash
go get github.com/axonops/audit/file
```

Requires Go 1.26+. See the [main README](../README.md) for transitive
dependencies.

## Quick start

The blank import registers the `file` output factory; the YAML
loader does the rest. Most consumers use the YAML path — see
[YAML configuration](#yaml-configuration) below.

For programmatic construction:

```go
import (
    "github.com/axonops/audit"
    "github.com/axonops/audit/file"
)

out, err := file.New(&file.Config{
    Path:       "/var/log/audit/events.log",
    MaxSizeMB:  100,
    MaxBackups: 5,
    MaxAgeDays: 30,
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

`Output.Write` is non-blocking: events are copied and enqueued onto an
internal buffered channel; a background `writeLoop` drains them and
batches each iteration into a single vectored write. Drops are
surfaced via `OutputMetrics.RecordDrop`. The parent directory of
`Path` MUST exist before `New` is called; the file itself is created
if missing.

## YAML configuration

```yaml
version: 1
app_name: "my-service"
host: "${HOSTNAME}"

outputs:
  audit_log:
    type: file
    file:
      path: "/var/log/audit/events.log"
      max_size_mb: 100
      max_backups: 5
      max_age_days: 30
      group_readable: false      # default — file mode 0o600
      compress: true             # default — gzip rotated backups
      fsync_each_batch: false    # default — page-cache durability
      buffer_size: 10000         # default — events dropped when full
```

A blank import registers the `file` output type with the YAML loader:

```go
import _ "github.com/axonops/audit/file"
```

The convenience [`outputs`][outputs] package blank-imports every
built-in backend in one line.

## Configuration reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | *(required)* | Filesystem path. Relative paths resolved to absolute at construction. Parent directory MUST exist. Symlinks in the parent path are rejected as a path-traversal defence. |
| `max_size_mb` | int | `100` | Rotate when the active file exceeds this many MiB. Max `10240` (10 GiB). |
| `max_backups` | int | `5` | Number of rotated backup files retained. Max `100`. Zero falls back to the default — there is no "keep all" mode. |
| `max_age_days` | int | `30` | Backups older than this are deleted. Max `365`. Zero falls back to the default — there is no "ignore age" mode. |
| `group_readable` | bool | `false` | When `false` the file is mode `0o600` (owner only). When `true` it is `0o640` (owner + group read) — required when a SIEM forwarder (Filebeat, Promtail, Fluentd) runs as a separate user in the file's group. World-readable and group-writable modes are not supported. |
| `compress` | bool | `true` | Gzip-compress rotated backup files asynchronously. JSON audit events typically compress 80–90 %. |
| `buffer_size` | int | `10000` | Internal async channel capacity. When full, new events are dropped and `OutputMetrics.RecordDrop` is called. Max `100000`. |
| `fsync_each_batch` | bool | `false` | When `true`, each batched `writev(2)` is followed by `fsync(2)` so the bytes are on stable storage before the writeLoop iteration returns. Trades 0.1–50 ms per batch (depending on storage) for per-batch durability. See [Durability contract][docs-durability] for the throughput model. |

## Durability

By default, batches land on the OS page cache when `writev(2)`
returns. A power loss between then and the kernel's next writeback
(typically 5–30 s on a default ext4 mount) can lose the most recent
batch — roughly 130 KiB at typical event sizes. For most audit
workloads this is comfortably inside compliance SLAs.

Set `fsync_each_batch: true` to eliminate this window at the cost of
per-batch fsync latency. The sustained event rate becomes
approximately `batch_size / (writev_latency + fsync_latency)`; on a
SATA SSD at 3 ms fsync per 256-event batch, that is about
85 k events/s. Higher producer rates surface as `RecordDrop` calls
from the internal channel.

`fsync_each_batch` does NOT fsync the parent directory on file
creation or rotation — for directory-level durability, mount the
audit-log directory with `dirsync`. See the [reference doc][docs] for
the full durability model.

## Rotation

Rotation fires when the active file exceeds `max_size_mb`. The file
descriptor is closed, the file is renamed with a timestamp suffix
(`events.log-2026-04-05T12-00-00.000`), and a new file is opened at
the original path. If `compress: true`, the rotated backup is gzipped
asynchronously. Backups are pruned by count (`max_backups`) and age
(`max_age_days`) after every rotation.

**Do not run the audit library's rotator alongside `logrotate(8)` on
the same file** — both tools rename out from under each other and you
get unpredictable backup chains. See [logrotate coexistence][docs-logrotate]
for the production guidance.

## Optional `RotationRecorder`

Per-output metrics (wired via `WithOutputMetrics` or the YAML factory)
MAY also implement `file.RotationRecorder`:

```go
type RotationRecorder interface {
    RecordRotation(path string)
}
```

If present, `RecordRotation` is called after each successful
rotation. Discovery is by structural typing — no explicit registration.
Precedent: `net/http.Flusher` on `http.ResponseWriter`.

## See also

- [Full output reference][docs] — config validation, file-permission
  enforcement, fsync error semantics, logrotate coexistence
- [Worked example][example] — `outputs.yaml` + `main.go` driving the
  file output end-to-end with rotation
- [Async delivery model](../docs/async-delivery.md) — two-level
  buffering, drop semantics, graceful shutdown
- [HMAC integrity](../docs/hmac-integrity.md) — tamper-evident audit
  trails configured per-output
- Related outputs:
  [`syslog`](../syslog/) (push to a SIEM via RFC 5424),
  [`webhook`](../webhook/) (push to an HTTPS endpoint),
  [`loki`](../loki/) (push to Grafana Loki),
  [`splunk`](../splunk/) (push to Splunk HEC)

[godoc]: https://pkg.go.dev/github.com/axonops/audit/file
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/file.svg
[audit-output]: https://pkg.go.dev/github.com/axonops/audit#Output
[docs]: ../docs/file-output.md
[docs-durability]: ../docs/file-output.md#durability-contract
[docs-logrotate]: ../docs/file-output.md#coexistence-with-logrotate
[example]: ../examples/03-file-output/
[outputs]: ../outputs/
