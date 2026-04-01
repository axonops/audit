# Architecture

This document describes the internal design of go-audit for contributors.
For usage documentation, see the [README](README.md) and [examples](examples/).

## Data Flow

```
caller goroutine                         drain goroutine
─────────────────                        ───────────────
AuditEvent(event)
  ├─ validate fields against EventDef
  ├─ check category enabled (atomic)
  └─ enqueue to buffered channel ──────► drainLoop reads from channel
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
github.com/axonops/go-audit           ← core (Logger, Output, taxonomy, formatters)
github.com/axonops/go-audit/file      ← file output (depends on core)
github.com/axonops/go-audit/syslog    ← syslog output (depends on core + srslog)
github.com/axonops/go-audit/webhook   ← webhook output (depends on core)
github.com/axonops/go-audit/outputconfig ← YAML config loader (depends on core + yaml.v3)
```

Outputs are separate Go modules so the core carries no third-party
output dependencies. A consumer importing only `go-audit/file` does
not pull in srslog or the webhook's SSRF filter.

The core module depends on `gopkg.in/yaml.v3` for `ParseTaxonomyYAML`.
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
    _ "github.com/axonops/go-audit/file"
    _ "github.com/axonops/go-audit/syslog"
    _ "github.com/axonops/go-audit/webhook"
)
```

## Thread Safety

- `AuditEvent()` is safe for concurrent use from multiple goroutines
- Category enable/disable uses `sync.Map` for lock-free reads on the hot path
- The single drain goroutine means `Output.Write` is never called concurrently
- `FormatOptions` is pre-allocated per output entry at construction; `FieldLabels` is
  set per-event in the drain goroutine (single writer, no lock needed)
- `Logger.Close()` is idempotent via `sync.Once`

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
