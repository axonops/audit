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
    RecordEvent(output, status string)          // "success" or "error" (non-DeliveryReporter outputs only)
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
logger, err := audit.NewLogger(
    audit.WithTaxonomy(tax),
    audit.WithMetrics(myPrometheusMetrics),
    audit.WithOutputs(fileOutput),
)
```

## 🔍 What to Monitor

### Critical — Alert Immediately

| Metric | Method | Meaning |
|--------|--------|---------|
| **Buffer drops** | `RecordBufferDrop()` | Events lost because the core intake queue is full. The application is producing events faster than the pipeline can drain. Increase `queue_size` in your outputs YAML or use `WithQueueSize()`. |
| **Output errors** | `RecordOutputError(output)` | An output failed to write. The syslog server may be down, the file system full, or the webhook endpoint unreachable. |

### Important — Monitor for Trends

| Metric | Method | Meaning |
|--------|--------|---------|
| **Delivery success/error** | `RecordEvent(output, "success"/"error")` | Per-output delivery outcome. A rising error rate indicates an output is degrading. |
| **Serialization errors** | `RecordSerializationError(eventType)` | The formatter failed to serialize an event. This usually indicates a bug in field values (e.g., a channel or function passed as a field value). |

### Informational — Track for Visibility

| Metric | Method | Meaning |
|--------|--------|---------|
| **Validation errors** | `RecordValidationError(eventType)` | Application code emitted an event with missing required fields or unknown event type. Fix the application code. |
| **Global filtered** | `RecordFiltered(eventType)` | Event silently discarded because its category is disabled. Expected behaviour, not a problem. |
| **Output filtered** | `RecordOutputFiltered(output)` | Event skipped by a per-output route filter. Expected behaviour. |

## Prometheus Example

```go
type prometheusMetrics struct {
    events       *prometheus.CounterVec
    bufferDrops  prometheus.Counter
    valErrors    *prometheus.CounterVec
    outputErrors *prometheus.CounterVec
}

func (m *prometheusMetrics) RecordEvent(output, status string) {
    m.events.WithLabelValues(output, status).Inc()
}

func (m *prometheusMetrics) RecordBufferDrop() {
    m.bufferDrops.Inc()
}

func (m *prometheusMetrics) RecordValidationError(eventType string) {
    m.valErrors.WithLabelValues(eventType).Inc()
}

// ... implement remaining methods
```

## 🚨 Recommended Alerts

| Alert | Condition | Action |
|-------|-----------|--------|
| Audit buffer drops | `RecordBufferDrop` > 0 in 5 minutes | Increase buffer size or investigate slow outputs |
| Output failure | `RecordOutputError` > threshold | Check output connectivity (syslog server, webhook endpoint, disk space) |
| Delivery error rate | `RecordEvent("error")` / total > 5% | Investigate failing output |
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

### Extension Interfaces

Output-specific metrics beyond the common five are available as
type-assertion extensions on the `OutputMetrics` value:

- `file.Metrics` — adds `RecordFileRotation(path string)` for tracking
  log rotation events
- `syslog.Metrics` — adds `RecordSyslogReconnect(address string,
  success bool)` for tracking reconnection attempts

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

// Extension: file.Metrics (detected via type assertion):
func (m *myOutputMetrics) RecordFileRotation(path string) { /* ... */ }

// Extension: syslog.Metrics (detected via type assertion):
func (m *myOutputMetrics) RecordSyslogReconnect(addr string, ok bool) { /* ... */ }
```

Consumers SHOULD embed `audit.NoOpOutputMetrics` for forward
compatibility — new methods added to the interface in future
versions will be absorbed by the embedded no-op.

## 🧪 Testing Metrics

The `audittest.MetricsRecorder` captures all metrics calls in memory:

```go
logger, _, metrics := audittest.NewLogger(t, taxonomyYAML)
// ... emit events ...
logger.Close()

assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
assert.Equal(t, 0, metrics.BufferDrops())
```

## 📚 Further Reading

- [Progressive Example: Capstone](../examples/17-capstone/) — Prometheus metrics integration
- [Async Delivery](async-delivery.md) — buffer sizing and backpressure
- [Testing](testing.md) — asserting on metrics in tests
- [API Reference: Metrics](https://pkg.go.dev/github.com/axonops/audit#Metrics)
