# ADR-0003: Single Configuration Pattern — Functional Options Only

## Status

Accepted — 2026-04-22

## Context

Prior to this decision, the audit library exposed two configuration
patterns for `audit.New`:

1. `audit.Config{}` struct + `audit.WithConfig(cfg)` option.
2. Individual functional options: `WithQueueSize(n)`,
   `WithShutdownTimeout(d)`, `WithValidationMode(m)`, `WithOmitEmpty()`.

The struct pattern carried a known footgun: `WithConfig` merged
non-zero fields only, so `OmitEmpty: false` in a caller-built struct
was indistinguishable from "not set". The library documented this by
introducing a dedicated `WithOmitEmpty()` option alongside the struct
— an explicit admission the struct pattern was broken for any
boolean field.

Beyond the bool-ambiguity, maintaining both patterns duplicated the
API surface:

- Consumers had to choose between two paths for the same outcome
  (no "one obvious way" per [PEP 20]).
- Every new config field required either a new option, a new struct
  field, or both — with no single source of truth.
- `outputconfig.Load` already unwound `Config` into individual
  options (`WithQueueSize`, `WithShutdownTimeout`, etc.) before
  passing to `audit.New`, so the struct never survived end-to-end.
- `Config.version` was unexported on the exported struct — a
  "confusing invariant" flagged by internal review. Schema
  versioning for outputs belongs in `outputconfig` YAML, not the
  programmatic API.

Empirical caller footprint (verified before the change):

- `audit.WithConfig(cfg)` callers: 2 tests + 1 `audittest` wrapper
  + 1 test. Zero production code, zero examples, zero
  `outputconfig` downstream path.
- `audit.Config{}` literals: test files + one internal
  `outputconfig.auditorConfigResult.config` field.

## Decision

**Remove `audit.Config` and `audit.WithConfig` from the public API.
Functional options become the sole configuration mechanism for
`audit.New`.**

Concretely:

- `audit.Config` renamed to unexported `audit.config` (pipeline-
  internal struct; invisible to consumers).
- `audit.WithConfig` deleted.
- `Config.version` field deleted entirely.
- Existing individual options (`WithQueueSize`, `WithShutdownTimeout`,
  `WithValidationMode`, `WithOmitEmpty`, `WithDisabled`,
  `WithSynchronousDelivery`, etc.) are unchanged and become the only
  way to configure an auditor programmatically.
- Consumers who previously wrote
  `audit.WithConfig(audit.Config{QueueSize: 500})` migrate to
  `audit.WithQueueSize(500)` — mechanical 1-line change.
- `outputconfig.Load`'s internal `auditorConfigResult` restructures
  to produce `[]audit.Option` directly rather than an
  `audit.Config`; consumers see no change.
- `audittest.WithConfig` wrapper is removed; consumers migrate to
  `audittest.WithAuditOption(audit.WithQueueSize(500))` (the
  existing pass-through option).

## Consequences

### Positive

- **Bool-ambiguity eliminated**: no more "is this `false` unset or
  explicit?" at the API level.
- **One obvious way**: consumers discover options via Go's
  auto-complete on `audit.With<tab>`; no parallel struct to learn.
- **Smaller public API surface**: 2 fewer exported symbols
  (`Config`, `WithConfig`) — locked in for v1.0.
- **Aligns with mature Go library patterns**: `log/slog`, `grpc`,
  `redis/go-redis`, `mongo/mongo-driver`, `net/http.ServeMux.Handle`
  — all use either pure functional options OR struct-as-sole-config,
  never both.
- **Schema-versioning correctness**: `outputconfig` YAML
  (`version: 1`) is now the single authoritative source for
  schema version metadata, so `outputconfig/migrate.go` has one
  migration contract instead of two.

### Negative

- **Breaking API change** (pre-v1.0, expected): any consumer with
  `audit.WithConfig(Config{X: v})` must migrate to `audit.WithX(v)`.
  Given the verified zero-production-caller footprint, real-world
  impact is minimal; `CHANGELOG.md` provides the migration recipe.
- **`outputconfig` internal pipeline rewrite**: `auditor_config.go`
  `parseAuditorConfig` restructures from populating an
  `audit.Config` to appending `audit.Option` values. No consumer
  behaviour change.
- **`audittest` wrapper removed**: `audittest.WithConfig(cfg)` → use
  `audittest.WithAuditOption(audit.WithQueueSize(n))` instead.

### Neutral

- Internal `audit.config` (unexported) continues to exist as the
  option-accumulator struct. Option functions write into
  `Auditor.cfg config` as before.

## Alternatives Considered

### Alternative A — keep `Config` + remove individual `WithX` options

**Rejected** because:

1. The bool-ambiguity footgun stays. `WithOmitEmpty` (which exists
   because `OmitEmpty bool` cannot be merged cleanly via the struct)
   would need to stay as a parallel option anyway.
2. Consumers must construct a full struct to change one field — no
   progressive disclosure.
3. Go stdlib has moved away from this pattern: `log/slog` replaces
   legacy `log.Logger`'s struct-heavy surface with attribute-based
   options; `http.ServeMux.Handle` uses functional options rather
   than a mux-config struct.

### Alternative B — keep both, document "prefer functional options"

**Rejected** because:

1. The issue explicitly calls for "exactly ONE pattern" (#579 AC1).
2. Documentation-only fixes don't eliminate the footgun; any
   consumer who copies an old example still hits it.
3. Every new config field still requires duplicate surface (option +
   field), doubling maintenance cost.

## References

- Issue #579 — this decision's originating audit finding.
- Dave Cheney, ["Functional options for friendly APIs"][cheney]
  (2014) — the canonical Go treatment of the pattern.
- [`log/slog`][slog] — `slog.New(handler)` + attribute-based
  options; legacy struct-heavy `log.Logger` surface reduced.
- [`grpc.DialOption`][grpc] — functional options are the sole
  dialer configuration path.
- [`redis.Options`][redis] — struct-as-options pattern used alone,
  no parallel functional options.
- [`mongo/options`][mongo] — ditto.
- [ADR-0001: Fields Ownership Contract](0001-fields-ownership-contract.md)
  — separate concern, kept for reference.

[cheney]: https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis
[slog]: https://pkg.go.dev/log/slog
[grpc]: https://pkg.go.dev/google.golang.org/grpc#DialOption
[redis]: https://pkg.go.dev/github.com/redis/go-redis/v9#Options
[mongo]: https://pkg.go.dev/go.mongodb.org/mongo-driver/mongo/options
