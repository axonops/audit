# v1.0 API changes — informational reference

This page lists every public-API and YAML field change introduced
during the v1.0 release-prep work. Pre-v1.0 versions of this
library were **explicitly unsupported** — the [README](../README.md)
has stated this since the project began, and the Go module
documentation carries the standard `v0.x` "unstable, may break"
warning. This document is therefore a *courtesy reference* for
anyone who experimented with a pre-v1.0 build informally; it is
**not** a migration guide and there is no commitment to a
step-by-step upgrade path.

If you need cross-library migration guidance (moving from
[logrus](https://github.com/sirupsen/logrus),
[zap](https://github.com/uber-go/zap),
[zerolog](https://github.com/rs/zerolog), etc. **into** this
library), see the dedicated guide at
[`docs/migrating-from-application-logging.md`](migrating-from-application-logging.md).
This page covers only changes *within* this library between
pre-v1.0 and v1.0.

## Contents

- [Logger → Auditor rename](#logger--auditor-rename)
- [YAML field renames](#yaml-field-renames)
- [Constructor and factory changes](#constructor-and-factory-changes)
- [Interface additions and signature changes](#interface-additions-and-signature-changes)
- [Type reorganisations](#type-reorganisations)
- [Removals](#removals)
- [New error sentinels](#new-error-sentinels)
- [Required config that wasn't required](#required-config-that-wasnt-required)
- [Code generation](#code-generation)
- [New types and interfaces](#new-types-and-interfaces)

---

## Logger → Auditor rename

The largest single source of API churn (#457). The library is an
*audit* logger, not an application logger, and the `Logger` name
collided pervasively with `slog.Logger` and consumer logging
frameworks across grep, IDE auto-complete, and prose.

| Before | After | Issue |
|---|---|---|
| `audit.Logger` (type) | `audit.Auditor` | #457 |
| `audit.NewLogger(...)` | `audit.New(...)` | #457 |
| `outputconfig.NewLogger(...)` | `outputconfig.New(...)` | #457 |
| `audit.WithLogger(*slog.Logger)` | `audit.WithDiagnosticLogger(*slog.Logger)` | #457 |
| `audit.LoggerReceiver` (interface) | `audit.DiagnosticLoggerReceiver` | #457 |
| `audit.Logger.Audit(...)` (method) | `audit.Auditor.AuditEvent(...)` | #457 |
| `audittest.NewLoggerQuick(...)` | `audittest.NewQuick(...)` | #457 |
| Receiver variable `l` | Receiver variable `a` | #457 |

Stdlib precedent: `database/sql.DB` not `Database`,
`http.Client` not `HTTPClient`, OpenTelemetry `trace.Tracer` not
`trace.Logger`.

## YAML field renames

| Before | After | Issue |
|---|---|---|
| `logger:` (top-level section) | `auditor:` | #457 |
| `auditor.buffer_size` | `auditor.queue_size` | #447 |
| `outputs.<name>.hmac.hash` | `outputs.<name>.hmac.algorithm` | #582 |
| Wire field `_hmac_v` (JSON output) | `_hmac_version` | #582 |
| Top-level `tls_policy:` | Removed — configure per-output | #476 |
| `loki.Config.Compress` (Go struct field) | `loki.Config.Gzip`. YAML key `gzip:` is unchanged — only programmatic Go callers need to rename. | #584 |

### New syslog batching fields (#599)

`syslog.Config` gained three new YAML keys with defaults:

| New key | Default | Purpose |
|---|---|---|
| `batch_size` | `100` | Maximum events per write call |
| `flush_interval` | `5s` | Maximum delay before flushing a partial batch |
| `max_batch_bytes` | `1 MiB` | Maximum bytes per write call |

**Behaviour change for existing consumers**: events may now wait
up to `flush_interval` (5 s default) before reaching the syslog
server. To restore pre-1.0 per-event delivery, set
`batch_size: 1`.

Old field names are rejected at load time with an `unknown field`
diagnostic that names the new field — typo or stale config
surfaces immediately rather than silently using a default.

CEF wire output retains `_hmacVersion` (pre-existing CEF naming
convention; only the JSON wire form changed in #582).

## Constructor and factory changes

### Stdout helpers

| Before | After | Issue |
|---|---|---|
| `audit.Stdout()` (panicked on error) | `audit.NewStdout() (*StdoutOutput, error)` | #578 |
| — (new) | `audit.NewStderr() (*StdoutOutput, error)` | #578 |
| — (new) | `audit.NewWriter(io.Writer) (*StdoutOutput, error)` | #578 |
| `init()` auto-registered the stdout factory | Consumers must blank-import `_ "github.com/axonops/audit/outputs"` or call `audit.RegisterOutputFactory("stdout", audit.StdoutFactory())` | #578 |

### File / syslog constructors

| Before | After | Issue |
|---|---|---|
| `file.New(Config, ...Option)` (value receiver) | `file.New(*Config, ...Option)` (pointer receiver) | #580 |
| `file.New(cfg, metrics, opts...)` (positional Metrics) | `file.New(cfg, opts...)` + `out.SetOutputMetrics(m)` post-construction | #579 |
| `syslog.New(cfg, metrics, opts...)` (positional Metrics) | `syslog.New(cfg, opts...)` + `out.SetOutputMetrics(m)` post-construction | #579 |

### Output factory contract

| Before | After | Issue |
|---|---|---|
| `OutputFactory func(name string, raw []byte, m audit.Metrics, l *slog.Logger) (Output, error)` (post-#490 form; the original pre-#490 signature had no `*slog.Logger` parameter) | `OutputFactory func(name string, raw []byte, m audit.Metrics, l *slog.Logger, fctx audit.FrameworkContext) (Output, error)` | #583 |
| `audit.RegisterOutputFactory(typeName, factory)` (panicked on bad input) | Returns `error` wrapping `audit.ErrValidation`. New `MustRegisterOutputFactory` retains the panic contract for `init()` callers. | #590 |

### Per-output factory wiring

| Before | After | Issue |
|---|---|---|
| Per-output module's own factory shape (varied) | All four output sub-modules expose identical `func NewFactory(factory audit.OutputMetricsFactory) audit.OutputFactory` | #581 |

## Interface additions and signature changes

### `audit.Event`

| Before | After | Issue |
|---|---|---|
| 2 methods (`Type() string`, `Fields() Fields`) | +3 methods: `Description() string`, `Categories() []CategoryInfo`, `FieldInfoMap() map[string]FieldInfo` | #597 |

Custom `Event` implementations must add the three new methods.
Generated builders (from `cmd/audit-gen`) carry full metadata
automatically; events constructed via `NewEvent` / `NewEventKV`
are taxonomy-agnostic and return zero values (empty string, nil,
nil).

### `audit.Metrics`

| Before | After | Issue |
|---|---|---|
| `RecordEvent(output string, status string)` | `RecordDelivery(output string, status audit.EventStatus)` | #594, #586 |

`status` is now a typed enum string with `audit.EventSuccess` /
`audit.EventError` constants — no more stringly-typed values.
Total interface method count remains 9 per ADR 0005.

### `audit.WithStandardFieldDefaults`

| Before | After | Issue |
|---|---|---|
| `WithStandardFieldDefaults(map[string]string)` | `WithStandardFieldDefaults(map[string]any)` | #595 |

Reserved standard fields with int / `time.Time` / etc. types
require the correct Go type; pre-1.0 stringly-typed defaults
silently coerced.

### `audit.NewEventKV`

| Before | After | Issue |
|---|---|---|
| `NewEventKV(eventType, kv...) Event` | `NewEventKV(eventType, kv...) (Event, error)` | #590 |

`MustNewEventKV` preserves the panic-on-error variant for
literal callsites.

### `Output.Write`

| Before | After | Issue |
|---|---|---|
| Accepted any payload size | Returns `audit.ErrEventTooLarge` (wraps `ErrValidation`) for events exceeding `MaxEventBytes` (default 1 MiB) | #688 |

### `audit.AuditEvent` / `EventHandle`

| Before | After | Issue |
|---|---|---|
| No `context.Context` variant | `Auditor.AuditEventContext(ctx, evt) error`; `EventHandle.AuditContext(ctx, fields)`; `EventHandle.AuditEventContext(ctx, evt)` | #600 |

Existing `AuditEvent(evt)` is now a `context.Background()`
convenience wrapper; the legacy non-ctx surface is unchanged.

## Type reorganisations

### HMAC configuration

| Before | After | Issue |
|---|---|---|
| `HMACConfig{SaltVersion string; SaltValue []byte}` | `HMACConfig{Salt audit.HMACSalt}` where `HMACSalt{Version string; Value []byte}` | #582 |

### Per-output extension interfaces

| Before | After | Issue |
|---|---|---|
| `file.Metrics` (interface with `RecordFileRotation(path string)`) | `file.RotationRecorder` with `RecordRotation(path string)` | #581 |
| `syslog.Metrics` (interface with `RecordSyslogReconnect(addr string, success bool)`) | `syslog.ReconnectRecorder` with `RecordReconnect(addr string, success bool)` | #581 |

### `outputconfig` public surface

| Before | After | Issue |
|---|---|---|
| `outputconfig.LoadResult` (exposed struct) | `outputconfig.Loaded` (opaque, accessor methods) | #577 |
| `outputconfig.NamedOutput` (exposed struct) | `outputconfig.OutputInfo` (renamed) | #577 |
| Single `outputconfig.New(ctx, yaml, path, opts...)` | `New(ctx, yaml, path, opts...)` for the simple case; `NewWithLoad(ctx, yaml, path, loadOpts, opts...)` for advanced wiring | #577 |

### Per-output option constructors

| Before | After | Issue |
|---|---|---|
| `audit.OutputRoute(...)` | `audit.WithRoute(...)` | #576 |
| `audit.OutputFormatter(...)` | `audit.WithOutputFormatter(...)` | #576 |
| `audit.OutputExcludeLabels(...)` | `audit.WithExcludeLabels(...)` | #576 |
| `audit.OutputHMAC(...)` | `audit.WithHMAC(...)` | #576 |

The `WithX` prefix is now consistent across every functional
option in the library.

## Removals

| Removed | Replacement / Rationale | Issue |
|---|---|---|
| `audit.Config` struct + `audit.WithConfig(*Config)` option | Functional options are now the sole mechanism: `WithQueueSize`, `WithShutdownTimeout`, etc. | #579 |
| Top-level `tls_policy:` YAML at root | Configure per-output (under `syslog:`, `webhook:`, `loki:`) and per secret-provider | #476 |
| `audit.Stdout()` (panic-on-error helper) | `audit.NewStdout() (*StdoutOutput, error)` | #578 |
| stdout auto-registration via `init()` | Blank-import `_ "github.com/axonops/audit/outputs"` or explicit `audit.RegisterOutputFactory(...)` | #578 |
| Positional `Metrics` parameter on `file.New` / `syslog.New` | `out.SetOutputMetrics(m)` post-construction (matches webhook / loki) | #579 |

## New error sentinels

The following are exported sentinels added during v1.0 work.
Consumers should discriminate via [`errors.Is`] rather than
string comparison; the error message text is not part of the
stable API.

[`errors.Is`]: https://pkg.go.dev/errors#Is

| Sentinel | Scenario | Issue |
|---|---|---|
| `audit.ErrTaxonomyRequired` | `audit.New` without `WithTaxonomy` (or `WithDisabled`) | #593 |
| `audit.ErrAppNameRequired` | `audit.New` without `WithAppName` (and not disabled) | #593 |
| `audit.ErrHostRequired` | `audit.New` without `WithHost` (and not disabled) | #593 |
| `audit.ErrEventTooLarge` | `Output.Write` event exceeds `MaxEventBytes` | #688 |
| `audit.ErrHMACMalformed` | HMAC verifier rejects malformed input | #483 |
| `audit.ErrUnknownFieldType` | Field value is a Go type the formatter doesn't support (e.g. `chan struct{}`) | #595 |
| `audit.ErrSSRFBlocked` (with typed `*SSRFBlockedError` carrying `Reason audit.SSRFReason`) | webhook / loki output rejects URL by SSRF policy | #480 |

`ErrTaxonomyRequired`, `ErrAppNameRequired`, `ErrHostRequired`,
`ErrEventTooLarge`, `ErrHMACMalformed`, and `ErrUnknownFieldType`
all wrap `audit.ErrValidation`, so
`errors.Is(err, audit.ErrValidation)` matches the broad class and
`errors.Is(err, audit.ErrAppNameRequired)` matches the specific
case. **`ErrSSRFBlocked` is the exception** — it does NOT wrap
`ErrValidation`; consumers handling SSRF blocks specifically
should use `errors.Is(err, audit.ErrSSRFBlocked)` (or
`errors.As(&ssrfErr)` for the typed `*SSRFBlockedError` carrying
the `Reason` field).

## Required config that wasn't required

| Field | Pre-v1.0 | v1.0 | Issue |
|---|---|---|---|
| `WithAppName` | Optional (silent empty value) | **Required**: `audit.New` returns `ErrAppNameRequired` | #593 |
| `WithHost` | Optional (silent empty value) | **Required**: `audit.New` returns `ErrHostRequired` | #593 |
| `WithTimezone` | Optional | Still optional — defaults to `time.Now().Location().String()` (always populated) | #593 |

`WithDisabled` skips both checks.

`audittest.New` / `audittest.NewQuick` carry test defaults
(`"audittest"` / `"localhost"`) so test code does not need to set
these explicitly.

## Code generation

`cmd/audit-gen` (the typed-builder generator) gained two
behaviour changes:

| Before | After | Issue |
|---|---|---|
| Custom field setters were `string`-typed regardless of YAML `type:` | Custom field setters typed per YAML annotation (`string` / `int` / `int64` / `float64` / `bool` / `time` / `duration`) | #575 |
| Generated builders had no taxonomy metadata accessor | Generated builders emit `FieldInfoMap() map[string]audit.FieldInfo` | #597 |
| Helper `intPtr` (collision-prone) | Helper renamed `auditIntPtr` | #575 |
| (no flag) | New `-standard-setters=all\|explicit` flag (default `all` for back-compat) | #575 |

## New types and interfaces

The following types / interfaces are entirely new in v1.0 — there
is no Before form. Names listed for discoverability.

| Symbol | Purpose | Issue |
|---|---|---|
| `audit.Sanitizer` (interface) | Privacy / compliance primitive: `SanitizeField(name, value) any`, `SanitizePanic(val) any`. Register via `audit.WithSanitizer`. | #598 |
| `audit.NoopSanitizer` (struct) | Embed-helper for `Sanitizer` (override only the method you care about) | #598 |
| `audit.SanitizerPanicSentinel` (constant) | `"[sanitizer_panic]"` — the value substituted when a `Sanitizer` panics | #598 |
| `audit.EventStatus` (string enum) | Typed status for `Metrics.RecordDelivery` (`EventSuccess` / `EventError`) | #586 |
| `audit.HMACSalt` (struct) | Replaces split `SaltVersion` / `SaltValue` fields | #582 |
| `audit.LastDeliveryReporter` (interface) | Per-output staleness signal: `LastDeliveryNanos() int64`. Used by `Auditor.LastDeliveryAge(name)`. | #753 |
| `audit.CategoryInfo` (struct) | Returned by `Event.Categories()`; carries name + optional severity | #597 |
| `audit.FieldInfo` (struct) | Returned by `Event.FieldInfoMap()`; carries name, required flag, sensitivity labels | #597 |
| `audit.FrameworkContext` (struct) | Carries app_name / host / timezone / pid into output factories | #583 |
| `audit.MinSeverity` / `audit.MaxSeverity` (constants) | Documented severity range bounds | #586 |

---

## Cross-references

- [`CHANGELOG.md`](../CHANGELOG.md) — full per-issue entries with
  rationale, behaviour notes, and rollback guidance.
- [`docs/migrating-from-application-logging.md`](migrating-from-application-logging.md)
  — cross-library migration from logrus / zap / zerolog **into**
  this library.
- [`README.md`](../README.md) "For Consumers" — the canonical
  starting point for new adopters; reads the v1.0 API directly
  with no pre-1.0 framing.

If a change appears below the threshold for this page (no public
type / YAML key / signature touched), see `CHANGELOG.md` directly.
