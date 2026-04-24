# ADR 0005: Metrics Interface Shape

- **Status:** Accepted (2026-04-24)
- **Issue:** [#594](https://github.com/axonops/audit/issues/594)
- **Reviewers:** api-ergonomics-reviewer (APPROVED)
- **Supersedes:** —

## Context

The audit pipeline exposes a pluggable instrumentation contract —
`audit.Metrics` — so consumers can wire their preferred telemetry
library (Prometheus, OpenTelemetry, Datadog, in-memory, etc.)
without the core library importing any concrete metrics
implementation. At the time of this ADR the contract has nine
methods:

```go
type Metrics interface {
    RecordSubmitted()
    RecordEvent(output string, status EventStatus)
    RecordOutputError(output string)
    RecordOutputFiltered(output string)
    RecordValidationError(eventType string)
    RecordFiltered(eventType string)
    RecordSerializationError(eventType string)
    RecordBufferDrop()
    RecordQueueDepth(depth, capacity int)
}
```

The audit of issue #594 identified two specific concerns:

1. **Consumer burden.** The capstone example's Prometheus adapter
   is roughly 200 lines — every method maps to a declared
   `*prometheus.CounterVec` or `prometheus.Gauge`, with label
   construction, constructor registration, and per-method wiring.
   A typical adopter wanting a Prometheus surface writes roughly
   150 lines of boilerplate.
2. **Method cardinality.** Nine methods is at the upper end of
   typical Go interface design — implementers have more to
   understand before they can get a working metrics surface.

The issue proposed two candidate shapes:

- **Option A** — single `Record(MetricEvent)` method where
  `MetricEvent` is a tagged union (`Kind MetricKind` plus a
  grab-bag of fields).
- **Option B** — split `Metrics` into composed sub-interfaces
  (`LifecycleMetrics`, `DeliveryMetrics`, `ValidationMetrics`) so
  consumers implement subsets.

A pre-coding consult with api-ergonomics-reviewer rejected both
in favour of a third option: **keep the existing nine methods,
address the real ergonomic concerns directly.**

## Decision

**Accept Option C — keep the nine-method `Metrics` interface.**
Ship the following changes in the #594 PR:

1. **Rename `RecordEvent(output, status)` → `RecordDelivery(output, status)`**
   to eliminate the semantic collision with `RecordSubmitted` in
   readers' heads. The new name matches the method's actual role
   (per-output delivery outcome, not event ingestion). Breaking
   pre-v1.
2. **Expand per-method godoc with cardinality guidance** so
   consumers choosing Prometheus label vectors see the label-
   space impact at a glance (e.g. `RecordSubmitted` is a single
   counter; `RecordValidationError(eventType)` is a vector keyed
   by event type — high cardinality if events proliferate).
3. **Document a forward-compatibility policy** in the interface
   godoc: adding a new metric in a v1.x release is a breaking
   interface change. The library adds new metrics via separate
   optional interfaces detected by type assertion on the
   `Metrics` value, mirroring the pattern already used for
   `DeliveryReporter`, `MetadataWriter`, `file.RotationRecorder`,
   and `syslog.ReconnectRecorder`. Consumers who embed
   `NoOpMetrics` automatically receive no-op default
   implementations of any new base-interface methods.
4. **Rewrite the capstone Prometheus adapter to ≤50 lines** using
   a table-driven registration pattern. The reduction in
   consumer boilerplate — from ~200 to ~50 — addresses the
   burden concern without changing the interface shape.
5. **Update `docs/metrics-monitoring.md`** to lead with the
   table-driven adapter pattern, include cardinality guidance
   per method, and document the forward-compat policy.

## Rationale

### Why neither Option A nor Option B

**Option A (tagged union)** reintroduces untyped payload
semantics. `MetricEvent.Depth` is meaningful only when `Kind ==
MetricQueueDepth`; `MetricEvent.Output` is meaningful only when
`Kind` is one of the output-scoped variants. The compiler cannot
prevent consumers from reading a meaningless field or from
forgetting to set a meaningful one. Prometheus adapters become a
nine-case switch on `Kind` — the same code as today with worse
branch prediction, worse discoverability in godoc, and an
allocation (the `MetricEvent` struct) on every invocation of
`RecordSubmitted`, which is called every event on the hot path.

**Option B (split interfaces)** introduces a silent-compile
footgun. A consumer who embeds `NoOpLifecycleMetrics` and
`NoOpDeliveryMetrics` but forgets `NoOpValidationMetrics`
compiles against the composed `Metrics` interface iff their type
happens to implement the three validation methods some other way
— a partial-interface satisfaction via accidental method sets.
The 9-method count is preserved; the only net change is
additional type-system ceremony and a new class of latent bugs.

### Why Option C is the right shape

**Stdlib precedent favours multi-method interfaces.**
`log/slog.Handler` has four methods. `net/http.ResponseWriter`
has three, plus a zoo of optional extensions (`http.Flusher`,
`http.Hijacker`, `http.Pusher`) detected by type assertion.
`database/sql/driver.Conn`, `Stmt`, and `Rows` each have four to
six. `prometheus.Collector` uses the "one interface per metric
type" pattern rather than a god-method. Go's idiom is "small
interfaces, many of them" — nine methods grouped by a clear
semantic (pipeline-level telemetry) is not anomalous.

**The actual complaint is consumer burden, not interface shape.**
Shrinking the capstone Prometheus adapter from ~200 to ≤50 lines
removes the ergonomic pain the issue identified, without
requiring every existing consumer to migrate to a new shape. The
table-driven registration pattern scales: adopters who adopt
cardinality-sensitive labels pay for them only at the vector they
construct. The `NoOpMetrics` embed pattern lets adopters opt into
instrumentation a method at a time.

**Forward-compat is cheaper via optional interfaces than via a
god-method.** When we need a tenth metric in v1.x, the new
optional interface is additive: consumers who want it implement
it, consumers who don't keep compiling. Contrast Option A, where
the "extension" is a new `MetricKind` constant — consumers who
switch on `Kind` without a `default` branch silently drop the
new metric, worse than a compile error.

## Forward-compatibility policy

New metrics added after v1.0 follow this pattern:

```go
// NewMetricRecorder is an optional extension interface. Consumers
// who want the new metric implement it; consumers who don't are
// unaffected. The library detects support via type assertion.
type NewMetricRecorder interface {
    RecordSomethingNew(arg Type)
}

// Inside the library:
if r, ok := a.metrics.(audit.NewMetricRecorder); ok {
    r.RecordSomethingNew(arg)
}
```

The precedent is `DeliveryReporter` on the output side (`output.go`),
and `file.RotationRecorder` / `syslog.ReconnectRecorder` on the
`OutputMetrics` side. The same shape applies here.

Methods already on `Metrics` stay on `Metrics`. We do not split
them out after the fact — that would be a breaking change. We only
add new methods via new optional interfaces.

## Consequences

### Positive

- No consumer-facing interface redesign; existing `Metrics`
  implementations continue to compile after a one-line
  `RecordEvent` → `RecordDelivery` find-and-replace.
- The capstone adapter's audit-side significant code is 34 lines
  (struct + `vec` helper + `newMetrics` constructor + seven
  `Record*` method implementations), measurably below the AC
  target of 50. That sets a realistic lower bound on the consumer
  burden — consumers who find the capstone "too much" can pick a
  strict subset by leaning on the `NoOpMetrics` embed.
- Forward-compat is explicit: extensions land as optional
  interfaces, consumers opt in per method.

### Negative / Accepted

- The nine-method count is unchanged — the discomfort some
  readers feel at the method list length is not mitigated by
  this decision. We accept that trade-off because the
  alternatives measurably worsen correctness (Option A) or add
  type-system ceremony without removing methods (Option B).
- `RecordEvent` → `RecordDelivery` is a breaking rename.
  Migration is mechanical (single find-and-replace) and is called
  out in the CHANGELOG `### Breaking Changes` section.

### Neutral

- `audit/metrics/prom` sub-module (drop-in Prometheus
  constructor) is tempting but DEFERRED to a follow-up issue.
  The capstone adapter already demonstrates the ≤50-line shape;
  elevating it to a blessed sub-module is a packaging concern,
  not an API-shape concern, and out of scope for v1.0.
- A sentinel value (`var DiscardMetrics Metrics = noOpMetrics{}`)
  is likewise deferred. `NoOpMetrics` stays an exported struct
  type so the embedding pattern continues to work; a sentinel
  style is additive and can ship later without breaking anyone.
- Splitting `Metrics` into composed sub-interfaces is rejected
  outright and should not be revisited without new evidence.

## References

- Issue #594 — bundled API-polish finding that triggered this
  decision.
- Issue #593 — B-45 option classification (`Metrics` is Optional
  tier, `audit.WithMetrics(nil)` accepted).
- `output.go` — `DeliveryReporter` precedent for optional-
  interface extension detection.
- api-ergonomics-reviewer consult transcript (2026-04-23).
