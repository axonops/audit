[&larr; Back to README](../README.md)

# Metrics and Monitoring

- [Why Monitor?](#-why-monitor-your-audit-pipeline)
- [The Metrics Interface](#the-metrics-interface)
- [What to Monitor](#-what-to-monitor)
- [Prometheus Example](#prometheus-example)
- [Recommended Alerts](#-recommended-alerts)
- [Per-Output Metrics](#-per-output-metrics)
- [Testing Metrics](#-testing-metrics)

## ❓ Why Monitor Your Audit Pipeline?

An audit pipeline that silently drops events is worse than no audit
pipeline at all — it gives a false sense of compliance. Monitoring
ensures you know when events are being dropped, when outputs are
failing, and when validation errors indicate application bugs.

## The Metrics Interface

go-audit defines a `Metrics` interface that you implement with your
metrics library (Prometheus, OpenTelemetry, Datadog, etc.). The core
library never imports a concrete metrics implementation.

```go
type Metrics interface {
    RecordEvent(output, status string)          // "success" or "error"
    RecordOutputError(output string)
    RecordOutputFiltered(output string)
    RecordValidationError(eventType string)
    RecordFiltered(eventType string)
    RecordSerializationError(eventType string)
    RecordBufferDrop()
}
```

### Wiring Metrics

```go
logger, err := audit.NewLogger(
    audit.Config{Version: 1, Enabled: true},
    audit.WithTaxonomy(tax),
    audit.WithMetrics(myPrometheusMetrics),
    audit.WithOutputs(fileOutput),
)
```

## 🔍 What to Monitor

### Critical — Alert Immediately

| Metric | Method | Meaning |
|--------|--------|---------|
| **Buffer drops** | `RecordBufferDrop()` | Events lost because the async buffer is full. The application is producing events faster than the pipeline can drain. Increase `Config.BufferSize` or investigate slow outputs. |
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

## 🔀 Per-Output Metrics

In addition to the global `Metrics` interface, each output type has
its own metrics interface for output-specific telemetry. These are
passed when constructing the output:

### File Output Metrics (`file.Metrics`)

```go
type Metrics interface {
    RecordFileRotation(path string) // called when a log file is rotated
}
```

Wire this to track how often rotation occurs and which paths are
being written to.

### Syslog Output Metrics (`syslog.Metrics`)

```go
type Metrics interface {
    RecordSyslogReconnect(address string, success bool) // called on reconnection attempt
}
```

Monitor reconnection attempts — frequent reconnections indicate
network instability or a failing syslog server.

### Webhook Output Metrics (`webhook.Metrics`)

```go
type Metrics interface {
    RecordWebhookDrop()                            // event dropped (internal buffer full)
    RecordWebhookFlush(batchSize int, dur time.Duration) // batch flushed successfully
}
```

Monitor `RecordWebhookDrop` — if this fires, the webhook's internal
buffer is full and events are being lost. Increase `buffer_size` in
the webhook configuration.

See [Progressive Example: CRUD API](../examples/09-crud-api/) for a
complete Prometheus implementation of all four metrics interfaces.

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

- [Progressive Example: CRUD API](../examples/09-crud-api/) — Prometheus metrics integration
- [Async Delivery](async-delivery.md) — buffer sizing and backpressure
- [Testing](testing.md) — asserting on metrics in tests
- [API Reference: Metrics](https://pkg.go.dev/github.com/axonops/go-audit#Metrics)
