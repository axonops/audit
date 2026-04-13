# Architecture

This document describes the internal design of audit for contributors.
For usage documentation, see the [README](README.md) and [examples](examples/).

## Data Flow

```
caller goroutine                         drain goroutine
─────────────────                        ───────────────
AuditEvent(event)
  ├─ validate fields against EventDef
  ├─ check category enabled (all enabled by default;
  │   DisableCategory() can disable at runtime)
  └─ enqueue to buffered channel ──────► drainLoop reads continuously
                                           ├─ set timestamp
                                           ├─ serialize with Formatter
                                           └─ fan-out to each outputEntry
                                                ├─ per-output route filter
                                                ├─ per-output sensitivity filter
                                                ├─ format (may differ per output)
                                                └─ Output.Write(bytes)
```

The **caller goroutine** does validation and a non-blocking channel send.
If the buffer is full, `AuditEvent` returns `ErrBufferFull` immediately.

The **drain goroutine** is the only goroutine that calls `Output.Write`,
so outputs do not need to be thread-safe. This also gives deterministic
event ordering within a single logger.

Delivery is **at-most-once** within a process lifetime. Events buffered
when `Close()` times out are lost.

## Module Boundaries

```
github.com/axonops/audit              ← core (Logger, Output, taxonomy, formatters)
github.com/axonops/audit/file         ← file output (depends on core)
github.com/axonops/audit/syslog       ← syslog output (depends on core + srslog)
github.com/axonops/audit/webhook      ← webhook output (depends on core)
github.com/axonops/audit/loki         ← Loki output (depends on core)
github.com/axonops/audit/outputconfig ← YAML config loader (depends on core + go-yaml)
github.com/axonops/audit/outputs      ← convenience: blank-import registers all outputs
github.com/axonops/audit/secrets      ← secret provider interface for ref+ URI resolution
```

Outputs are separate Go modules so the core carries no third-party
output dependencies. A consumer importing only `audit/file` does
not pull in srslog or the webhook's SSRF filter.

The core module depends on `github.com/goccy/go-yaml` for `ParseTaxonomyYAML`.
`StdoutOutput` ships with core and has no extra dependencies.

## Factory Registry

The `outputconfig` package creates outputs from YAML type strings
(`"file"`, `"syslog"`, `"webhook"`) without the core importing every
output module. This works via a factory registry:

1. Each output module registers a factory in its `init()` function
2. `outputconfig.Load` calls `audit.LookupOutputFactory(typeName)` to
   find the factory
3. Consumers activate factories via blank imports:

```go
import (
    _ "github.com/axonops/audit/file"
    _ "github.com/axonops/audit/syslog"
    _ "github.com/axonops/audit/webhook"
)
```

## Thread Safety

- `AuditEvent()` is safe for concurrent use from multiple goroutines
- Category enable/disable uses `sync.Map` for lock-free reads on the hot path
- The single drain goroutine means `Output.Write` is never called concurrently
- `FormatOptions` is pre-allocated per output entry at construction; `FieldLabels` is
  set per-event in the drain goroutine (single writer, no lock needed)
- `Logger.Close()` is idempotent via `sync.Once`

## Field Categories

The library distinguishes three categories of event fields:

| Category | Examples | Declared in taxonomy? | Strippable? |
|----------|----------|----------------------|-------------|
| **Framework fields** | `timestamp`, `event_type`, `severity`, `app_name`, `host`, `timezone`, `pid`, `event_category`, `duration_ms` | No — injected by the library | No — always present |
| **Reserved standard fields** | `actor_id`, `source_ip`, `reason`, `target_id` (31 total) | Optional — can be required or labeled | Yes — via sensitivity labels |
| **User-defined fields** | Application-specific fields | Yes — in taxonomy YAML | Yes — via sensitivity labels |

Framework fields are set once at logger construction (`WithAppName`, `WithHost`,
`WithTimezone`; `pid` auto-captured via `os.Getpid()`). They appear in every
serialised event before user fields.

Reserved standard fields are well-known audit names that are always accepted
without taxonomy declaration. They have generated setter methods on every builder
and map to standard ArcSight CEF extension keys.

## Key Files

| File | Purpose |
|------|---------|
| `audit.go` | `Logger`, `NewLogger`, `AuditEvent`, `Close`, drain goroutine |
| `event.go` | `Event` interface, `NewEvent`, `EventType` handle, `FieldInfo`, `CategoryInfo` |
| `taxonomy.go` | `Taxonomy`, `EventDef`, `CategoryDef`, validation, sensitivity pre-computation |
| `taxonomy_yaml.go` | `ParseTaxonomyYAML`, YAML deserialization, `ErrInvalidInput` |
| `config.go` | `Config`, `ValidationMode`, defaults and limits |
| `options.go` | Functional options: `WithTaxonomy`, `WithOutputs`, `WithNamedOutput` |
| `output.go` | `Output` interface, `DestinationKeyer`, `DeliveryReporter` |
| `fanout.go` | `outputEntry`, per-output routing/formatting/sensitivity orchestration |
| `filter.go` | `EventRoute`, `MatchesRoute`, `ValidateEventRoute` |
| `format.go` | `Formatter` interface, `FormatOptions`, `IsExcluded` |
| `format_json.go` | `JSONFormatter` — deterministic field order JSON |
| `format_cef.go` | `CEFFormatter` — Common Event Format for SIEMs |
| `middleware.go` | HTTP middleware, `Hints`, `EventBuilder` |
| `transport.go` | `TransportMetadata`, response writer wrapper |
| `metrics.go` | `Metrics` interface |
| `registry.go` | `OutputFactory` registry (`RegisterOutputFactory`, `LookupOutputFactory`) |
| `stdout.go` | `StdoutOutput` — simple io.Writer output |
| `tls_policy.go` | `TLSPolicy` — shared TLS version/cipher configuration |
| `migrate.go` | Taxonomy version migration |
