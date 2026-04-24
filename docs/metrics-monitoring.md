[&larr; Back to README](../README.md)

# Metrics and Monitoring

- [Why Monitor?](#why-monitor-your-audit-pipeline)
- [The Metrics Interface](#the-metrics-interface)
- [What to Monitor](#what-to-monitor)
- [Prometheus Example](#prometheus-example)
- [Recommended Alerts](#recommended-alerts)
- [Per-Output Metrics](#per-output-metrics)
- [Testing Metrics](#testing-metrics)

## ❓ Why Monitor Your Audit Pipeline?

An audit pipeline that silently drops events is worse than no audit
pipeline at all — it gives a false sense of compliance. Monitoring
ensures you know when events are being dropped, when outputs are
failing, and when validation errors indicate application bugs.

## The Metrics Interface

audit defines a `Metrics` interface that you implement with your
metrics library (Prometheus, OpenTelemetry, Datadog, etc.). The core
library never imports a concrete metrics implementation.

```go
type Metrics interface {
    RecordSubmitted()                           // total events entering the pipeline
    RecordDelivery(output string, status EventStatus) // EventSuccess / EventError — see "Drop vs delivery error" below
    RecordOutputError(output string)
    RecordOutputFiltered(output string)
    RecordValidationError(eventType string)
    RecordFiltered(eventType string)
    RecordSerializationError(eventType string)
    RecordBufferDrop()
    RecordQueueDepth(depth, capacity int)       // sampled every 64 events
}
```

### Wiring Metrics

```go
auditor, err := audit.New(
    audit.WithTaxonomy(tax),
    audit.WithMetrics(myPrometheusMetrics),
    audit.WithOutputs(fileOutput),
)
```

### Interface design — nine methods, stable shape

The interface has nine methods. That shape is intentional and locked
for v1.0 by [ADR 0005](adr/0005-metrics-interface-shape.md), which
considered and rejected two alternatives: a single-method
`Record(MetricEvent)` tagged union, and a split into
`LifecycleMetrics` / `DeliveryMetrics` / `ValidationMetrics` composed
sub-interfaces.

Why the nine-method shape won:

- **Stdlib precedent.** `log/slog.Handler` has four methods;
  `net/http.ResponseWriter` has three plus a zoo of optional
  extensions detected by type assertion (`http.Flusher`,
  `http.Hijacker`). `database/sql/driver.Conn`, `Stmt`, and `Rows`
  each have four to six. Go culture is "small interfaces, many of
  them" — not "one god-method that dispatches on a tag." Nine
  methods grouped by purpose is not anomalous.
- **Typed arguments beat tagged unions.** `RecordValidationError`
  takes a typed `eventType string`; `RecordQueueDepth` takes typed
  `depth, capacity int`. A single `Record(MetricEvent)` would
  reintroduce untyped payload where `Depth` is meaningful only when
  `Kind == MetricQueueDepth` — a `map[string]any` with extra steps.
- **Forward-compat via optional interfaces.** New metrics added in
  future releases land as separate optional interfaces detected via
  type assertion (same pattern as `DeliveryReporter`,
  `file.RotationRecorder`, `syslog.ReconnectRecorder`). Consumers
  embedding `NoOpMetrics` retain no-op defaults for every method.

The real cost — consumer boilerplate — is addressed by shipping a
compact Prometheus adapter pattern (~35 lines of significant code;
see the capstone example at `examples/17-capstone/metrics.go`).

## 🔍 What to Monitor

### Critical — Alert Immediately

| Metric | Method | Meaning |
|--------|--------|---------|
| **Buffer drops** | `RecordBufferDrop()` | Events lost because the core intake queue is full. The application is producing events faster than the pipeline can drain. Increase `queue_size` in your outputs YAML or use `WithQueueSize()`. |
| **Output errors** | `RecordOutputError(output)` | An output failed to write. The syslog server may be down, the file system full, or the webhook endpoint unreachable. |

### Important — Monitor for Trends

| Metric | Method | Meaning |
|--------|--------|---------|
| **Delivery success/error** | `RecordDelivery(output, EventSuccess/EventError)` | Per-output delivery outcome. A rising error rate indicates an output is degrading. |
| **Serialization errors** | `RecordSerializationError(eventType)` | The formatter failed to serialize an event. This usually indicates a bug in field values (e.g., a channel or function passed as a field value). |

### Informational — Track for Visibility

| Metric | Method | Meaning |
|--------|--------|---------|
| **Validation errors** | `RecordValidationError(eventType)` | Application code emitted an event with missing required fields or unknown event type. Fix the application code. |
| **Global filtered** | `RecordFiltered(eventType)` | Event silently discarded because its category is disabled. Expected behaviour, not a problem. |
| **Output filtered** | `RecordOutputFiltered(output)` | Event skipped by a per-output route filter. Expected behaviour. |

## Prometheus Example

A complete Prometheus adapter fits in about 35 lines of significant
code using a small `vec()` helper and `NoOpMetrics` embedding. The
capstone example (`examples/17-capstone/metrics.go`) ships the full
implementation; the core shape is:

```go
type prometheusMetrics struct {
    audit.NoOpMetrics // forward-compat: new Metrics methods default to no-op

    delivery, outputErr, outputFilt       *prometheus.CounterVec
    valErr, filt, serErr                  *prometheus.CounterVec
    bufferDrops                           prometheus.Counter
}

func vec(name, help string, labels ...string) *prometheus.CounterVec {
    return promauto.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

func newMetrics() *prometheusMetrics {
    return &prometheusMetrics{
        delivery:    vec("audit_events_total", "Audit deliveries.", "output", "status"),
        outputErr:   vec("audit_output_errors_total", "Output write errors.", "output"),
        outputFilt:  vec("audit_output_filtered_total", "Events filtered per output.", "output"),
        valErr:      vec("audit_validation_errors_total", "Validation errors.", "event_type"),
        filt:        vec("audit_filtered_total", "Globally filtered events.", "event_type"),
        serErr:      vec("audit_serialization_errors_total", "Serialization errors.", "event_type"),
        bufferDrops: promauto.NewCounter(prometheus.CounterOpts{
            Name: "audit_buffer_drops_total", Help: "Events dropped due to full buffer.",
        }),
    }
}

// EventStatus is a typed string so string(status) is a zero-cost
// conversion — pass it straight to WithLabelValues.
func (m *prometheusMetrics) RecordDelivery(output string, status audit.EventStatus) {
    m.delivery.WithLabelValues(output, string(status)).Inc()
}
func (m *prometheusMetrics) RecordOutputError(output string)    { m.outputErr.WithLabelValues(output).Inc() }
func (m *prometheusMetrics) RecordOutputFiltered(output string) { m.outputFilt.WithLabelValues(output).Inc() }
func (m *prometheusMetrics) RecordValidationError(ev string)    { m.valErr.WithLabelValues(ev).Inc() }
func (m *prometheusMetrics) RecordFiltered(ev string)           { m.filt.WithLabelValues(ev).Inc() }
func (m *prometheusMetrics) RecordSerializationError(ev string) { m.serErr.WithLabelValues(ev).Inc() }
func (m *prometheusMetrics) RecordBufferDrop()                  { m.bufferDrops.Inc() }
```

`RecordSubmitted` and `RecordQueueDepth` are inherited no-ops from the
embedded `audit.NoOpMetrics`; wire them yourself if you want those
counters on your dashboard.

### Cardinality guidance

Each method's Prometheus label dimensionality is documented in the
[`Metrics` interface godoc](https://pkg.go.dev/github.com/axonops/audit#Metrics).
Pay particular attention to event-type-labelled methods
(`RecordValidationError`, `RecordFiltered`, `RecordSerializationError`):
if your taxonomy is large or unknown event types can leak through,
these vectors become high-cardinality. Budget accordingly, or drop
the `event_type` label on methods where you only need a global count.

## 📊 Event Accounting

The pipeline metrics form a closed accounting equation:

```
submitted = filtered + validation_errors + buffer_drops
            + serialization_errors + reached_fanout

Per output:
  reached_fanout = delivered + output_filtered + output_error
                   + output_buffer_drops
```

Where:
- `submitted` = `RecordSubmitted()` count
- `filtered` = `RecordFiltered()` count (global category filter)
- `buffer_drops` = `RecordBufferDrop()` count (core queue full)
- `output_buffer_drops` = `OutputMetrics.RecordDrop()` count
- `delivered` = `OutputMetrics.RecordFlush()` count

### Drop vs delivery error

Every self-reporting output (file, syslog, webhook, loki) follows
the same rule for drop-vs-error reporting:

| Outcome | `OutputMetrics.RecordDrop()` | `Metrics.RecordDelivery(_, EventError)` |
|---|---|---|
| Event rejected before queue (oversize, buffer full) | ✓ | ✗ |
| Delivery attempted, all retries exhausted (webhook, loki) | ✓ | ✓ |
| Delivery succeeded | ✗ | `RecordDelivery(_, EventSuccess)` via `OutputMetrics.RecordFlush` |

Buffer drops count only via per-output `RecordDrop` because the event
never reached the destination — there is nothing to report as a
delivery outcome. Retry-exhaustion failures in webhook and loki count
via BOTH `RecordDrop` and `RecordDelivery(EventError)`: `RecordDrop`
because the event is lost, and `RecordDelivery(EventError)` because the
output did attempt delivery and all retries failed — that is a
genuine delivery-error signal. File and syslog do not have retries
(they write synchronously once dequeued) so they only ever report
via `RecordDrop`.

Consumers that want a single "events lost" counter should sum
`RecordBufferDrop` (core queue) + per-output `RecordDrop` (this
already includes retry-exhaustion drops for webhook/loki, so no
double-counting with `RecordDelivery(EventError)` is needed).

## 🚨 Recommended Alerts

| Alert | Condition | Action |
|-------|-----------|--------|
| Audit buffer drops | `RecordBufferDrop` > 0 in 5 minutes | Increase buffer size or investigate slow outputs |
| Output failure | `RecordOutputError` > threshold | Check output connectivity (syslog server, webhook endpoint, disk space) |
| Delivery error rate | `RecordDelivery(_, EventError)` / total > 5% | Investigate failing output |
| Validation spike | `RecordValidationError` > threshold | Application bug — check recent deployments |

## 🔀 Per-Output Metrics (`OutputMetrics`)

Every async output (file, syslog, webhook, Loki) can receive a
scoped metrics instance via the unified `OutputMetrics` interface.
This replaces the old per-output interfaces (`webhook.Metrics`,
`loki.Metrics`) with a single interface for all outputs:

```go
type OutputMetrics interface {
    RecordDrop()                              // event dropped (internal buffer full)
    RecordFlush(batchSize int, dur time.Duration) // batch/event written successfully
    RecordError()                             // non-retryable delivery error
    RecordRetry(attempt int)                  // retry attempt (1-indexed)
    RecordQueueDepth(depth, capacity int)     // buffer pressure gauge
}
```

### Wiring via `OutputMetricsFactory`

The factory creates a scoped instance per output, labelled by type
and name:

```go
factory := func(outputType, outputName string) audit.OutputMetrics {
    return &myOutputMetrics{
        drops: dropsVec.WithLabelValues(outputType, outputName),
        // ...
    }
}

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithOutputMetrics(factory),
)
```

The `outputType` is the output kind (e.g., "file", "syslog",
"webhook", "loki"). The `outputName` is the consumer-chosen YAML key
(e.g., "compliance_archive", "security_feed"). Together they allow
fully scoped Prometheus labels.

### Unified `NewFactory` Pattern

Every output sub-module (`file`, `syslog`, `webhook`, `loki`) exposes
the same `NewFactory` signature:

```go
func NewFactory(factory audit.OutputMetricsFactory) audit.OutputFactory
```

Pass `nil` to opt out of per-output metrics (the output uses a no-op
recorder). Pass a populated `OutputMetricsFactory` to wire custom
per-output metrics:

```go
import (
    "github.com/axonops/audit"
    "github.com/axonops/audit/file"
    "github.com/axonops/audit/syslog"
    "github.com/axonops/audit/webhook"
    "github.com/axonops/audit/loki"
)

func init() {
    // Identical signature across all four outputs.
    audit.RegisterOutputFactory("file",    file.NewFactory(myFactory))
    audit.RegisterOutputFactory("syslog",  syslog.NewFactory(myFactory))
    audit.RegisterOutputFactory("webhook", webhook.NewFactory(myFactory))
    audit.RegisterOutputFactory("loki",    loki.NewFactory(myFactory))
}
```

The output modules also register a no-op default via `init()`, so
`_ "github.com/axonops/audit/file"` still works when you don't need
custom metrics.

### Extension Interfaces

Output-specific metrics beyond the common five are available as
type-assertion extensions on the `OutputMetrics` value:

- `file.RotationRecorder` — adds `RecordRotation(path string)` for
  tracking log rotation events
- `syslog.ReconnectRecorder` — adds `RecordReconnect(address string,
  success bool)` for tracking reconnection attempts

The naming follows the Go stdlib `-er` convention for single-method
extension interfaces that layer additional capability onto a base
contract: `http.Flusher` / `http.Hijacker` on top of
`http.ResponseWriter`, and `sql/driver.Queryer` / `Execer` on top of
`driver.Conn`.

To receive extension callbacks, your `OutputMetrics` implementation
must also satisfy the extension interface:

```go
type myOutputMetrics struct {
    audit.NoOpOutputMetrics // embed for forward compatibility
    drops prometheus.Counter
    // ...
}

// Core OutputMetrics methods:
func (m *myOutputMetrics) RecordDrop() { m.drops.Inc() }

// Extension: file.RotationRecorder (detected via type assertion):
func (m *myOutputMetrics) RecordRotation(path string) { /* ... */ }

// Extension: syslog.ReconnectRecorder (detected via type assertion):
func (m *myOutputMetrics) RecordReconnect(addr string, ok bool) { /* ... */ }
```

Consumers SHOULD embed `audit.NoOpOutputMetrics` for forward
compatibility — new methods added to the interface in future
versions will be absorbed by the embedded no-op.

## 🧪 Testing Metrics

The `audittest.MetricsRecorder` captures all metrics calls in memory:

```go
auditor, _, metrics := audittest.New(t, taxonomyYAML)
// ... emit events ...
auditor.Close()

assert.Equal(t, 1, metrics.EventDeliveries("recorder", audit.EventSuccess))
assert.Equal(t, 0, metrics.BufferDrops())
```

## 📚 Further Reading

- [Progressive Example: Capstone](../examples/17-capstone/) — Prometheus metrics integration
- [Async Delivery](async-delivery.md) — buffer sizing and backpressure
- [Testing](testing.md) — asserting on metrics in tests
- [API Reference: Metrics](https://pkg.go.dev/github.com/axonops/audit#Metrics)
