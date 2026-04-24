[&larr; Back to README](../README.md)

# Writing Custom Outputs

This guide explains how to implement a custom audit output for audit.

- [Interface Hierarchy](#interface-hierarchy)
- [Decision Tree](#decision-tree)
- [Minimal Output](#minimal-output)
- [Adding MetadataWriter](#adding-metadatawriter)
- [Async Delivery](#async-delivery)
- [Receiving Per-Output Metrics](#receiving-per-output-metrics)
- [Reporting Delivery Outcomes](#reporting-delivery-outcomes)
- [Thread Safety](#thread-safety)

## Interface Hierarchy

Every output implements the base `audit.Output` interface. Additional
optional interfaces add capabilities:

```
Output (required)
├── MetadataWriter         — receive structured event metadata (type, severity, category)
├── FrameworkFieldReceiver — receive app_name, host, timezone, pid at startup
├── DiagnosticLoggerReceiver         — receive the library's slog.Logger for diagnostics
├── DestinationKeyer       — prevent duplicate outputs to the same destination
├── OutputMetricsReceiver  — receive per-output delivery metrics
└── DeliveryReporter       — signal that delivery metrics are recorded after actual I/O
```

## Decision Tree

| Question | Interface |
|----------|-----------|
| Do you need event type, severity, or category? | Implement `MetadataWriter` |
| Do you need app_name/host for labelling? | Implement `FrameworkFieldReceiver` |
| Do you want the library's diagnostic logger? | Implement `DiagnosticLoggerReceiver` |
| Can two outputs point to the same destination? | Implement `DestinationKeyer` |
| Does your output want per-output drop/flush/error metrics? | Implement `OutputMetricsReceiver` |
| Does your output use a background goroutine that records delivery outcomes after actual I/O? | Implement `DeliveryReporter` |

## Minimal Output

A minimal output implements only the `Output` interface. This pattern
is appropriate for synchronous, non-I/O outputs such as in-process
sinks, test recorders, and channel-based outputs. For outputs that
perform network or file I/O, see [Async Delivery](#async-delivery).

All `OutputFactory` implementations MUST call `WrapOutput` to set
the consumer-chosen output name. The `name` argument passed to the
factory is the YAML config key (e.g. `compliance_file`) —
`WrapOutput` installs this as the output's `Name()`. Without it,
`output.Name()` returns whatever the inner type returns, which
causes mismatched metrics labels and log messages. See
[WrapOutput Transparency](#wrapoutput-transparency).

```go
type MyOutput struct {
    name string
    mu   sync.Mutex
}

func (o *MyOutput) Name() string      { return o.name }
func (o *MyOutput) Write(data []byte) error {
    o.mu.Lock()
    defer o.mu.Unlock()
    // Write data to your destination
    return nil
}
func (o *MyOutput) Close() error { return nil }
```

Register it via a factory:

```go
func init() {
    audit.RegisterOutputFactory("my-output", func(name string, rawConfig []byte, coreMetrics audit.Metrics, logger *slog.Logger, fctx audit.FrameworkContext) (audit.Output, error) {
        // coreMetrics is the pipeline-level Metrics instance (may be nil).
        // Per-output metrics are injected separately via SetOutputMetrics —
        // see "Receiving Per-Output Metrics" below.
        //
        // logger is the auditor's diagnostic logger, threaded through
        // outputconfig.WithDiagnosticLogger / audit.WithDiagnosticLogger.
        // Route construction-time warnings here (TLS policy, permission
        // mode) so they reach the consumer's configured handler rather
        // than slog.Default. A nil logger is valid; treat it as
        // slog.Default.
        return audit.WrapOutput(&MyOutput{name: name}, name), nil
    })
}
```

## Adding MetadataWriter

If your output needs event type or severity for routing or labelling:

```go
func (o *MyOutput) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
    // meta.EventType, meta.Severity, meta.Category, meta.Timestamp available
    return o.Write(data)
}
```

When an output implements `MetadataWriter`, the library calls
`WriteWithMetadata` instead of `Write`.

## Async Delivery

`Write` is called from the library's single drain goroutine. A slow or
stalled `Write` blocks event delivery to every subsequent output in
the fan-out, for every event. Any output that performs network I/O,
file I/O, or any operation with unpredictable latency MUST use async
delivery.

### The Pattern

All four built-in I/O outputs (file, syslog, webhook, loki) follow
the same pattern:

1. `Write` copies the data, sends to an internal buffered channel via
   a non-blocking `select`, and returns immediately.
2. A background goroutine reads from the channel and performs the
   actual I/O.
3. If the channel is full, the event is dropped and a metric is
   recorded — `Write` returns `nil` (not an error).

### Buffer Ownership and Retention

The `data []byte` argument to `Write` MUST be copied before being
retained past the call. This is **load-bearing**: since W2 (#497) the
library leases `data`'s backing array from a pool, zero-fills it on
release, and reuses it for the next event. Retaining `data` (or any
slice that aliases its backing array) without copying causes **silent
cross-event data corruption** — the bytes a background goroutine reads
later belong to a different event or are zero-filled. For HMAC-signed
outputs, retained bytes additionally fail integrity verification at
the receiver because the bytes-as-sent no longer match the bytes the
HMAC was computed over.

The same slice is passed to multiple outputs during fan-out, so
per-output retention is unsafe even before pool recycling happens.

Always copy defensively. The canonical idiom is:

```go
cp := append([]byte(nil), data...)
```

(The `make([]byte, len(data)) + copy(cp, data)` pattern is equivalent;
`append` is the established Go idiom and avoids the two-step.)

A synchronous output that writes and returns is safe without copying.
Any output that retains `data` for asynchronous delivery, batching,
testing, or any other reason MUST copy first.

See [`docs/performance.md` — The `Output.Write` retention contract](performance.md#the-outputwrite-retention-contract)
for the W2 drain pipeline details that make this contract
load-bearing.

### Drop-on-Full Behaviour

When the channel is full, the correct behaviour is to drop the event
and call `OutputMetrics.RecordDrop()`. For `DeliveryReporter` outputs
(see [Reporting Delivery Outcomes](#reporting-delivery-outcomes)),
returning `nil` from `Write` on a drop is correct — the drop is
accounted for by `OutputMetrics.RecordDrop()`, and the core library
does not call `Metrics.RecordDelivery` for self-reporting outputs.

There are two distinct cases for `Write`'s return value:

- **Buffer full**: return `nil` — the drop is recorded via
  `OutputMetrics.RecordDrop()`, not via an error.
- **Output closed**: return `audit.ErrOutputClosed` — the drain
  goroutine logs this and records it as an output error. All built-in
  async outputs check `closed.Load()` at the top of `Write` and return
  this sentinel.

### Buffer Size

Make the buffer size configurable via the output's config struct, not
hardcoded. All four built-in async outputs (file, syslog, webhook,
loki) expose `BufferSize` in their configs. File and syslog use
default 10,000 (max 100,000); webhook and loki use default 10,000
(max 1,000,000).

### Async Output Skeleton

```go
type AsyncOutput struct {
    name    string
    ch      chan []byte
    closeCh chan struct{}
    done    chan struct{}
    closed  atomic.Bool
    mu      sync.Mutex // guards Close against concurrent Write
    // ... your I/O resources (conn, file, etc.)

    outputMetrics atomic.Pointer[audit.OutputMetrics]
}

func NewAsyncOutput(name string, bufferSize int) *AsyncOutput {
    o := &AsyncOutput{
        name:    name,
        ch:      make(chan []byte, bufferSize),
        closeCh: make(chan struct{}),
        done:    make(chan struct{}),
    }
    go o.writeLoop()
    return o
}

func (o *AsyncOutput) Name() string { return o.name }

func (o *AsyncOutput) Write(data []byte) error {
    if o.closed.Load() {
        return audit.ErrOutputClosed
    }
    cp := make([]byte, len(data))
    copy(cp, data)

    select {
    case o.ch <- cp:
        return nil
    default:
        // Buffer full — drop the event.
        // Note: built-in outputs rate-limit this warning to at most
        // once per 10 seconds. See file/droplimit.go for the pattern.
        if omp := o.outputMetrics.Load(); omp != nil {
            (*omp).RecordDrop()
        }
        return nil
    }
}

func (o *AsyncOutput) writeLoop() {
    defer close(o.done)
    for {
        select {
        case data := <-o.ch:
            start := time.Now()
            err := o.doWrite(data)
            if omp := o.outputMetrics.Load(); omp != nil {
                if err != nil {
                    (*omp).RecordError()
                } else {
                    (*omp).RecordFlush(1, time.Since(start))
                }
            }
        case <-o.closeCh:
            o.drainRemaining()
            return
        }
    }
}

func (o *AsyncOutput) drainRemaining() {
    for {
        select {
        case data := <-o.ch:
            _ = o.doWrite(data) // best-effort during shutdown
        default:
            return
        }
    }
}

func (o *AsyncOutput) doWrite(data []byte) error {
    // Replace with your actual I/O: HTTP POST, file write, etc.
    return nil
}

func (o *AsyncOutput) Close() error {
    o.mu.Lock()
    defer o.mu.Unlock()

    if !o.closed.CompareAndSwap(false, true) {
        return nil
    }
    close(o.closeCh)

    timer := time.NewTimer(10 * time.Second)
    defer timer.Stop()

    select {
    case <-o.done:
    case <-timer.C:
        // Shutdown timeout — remaining events lost.
    }
    return nil
}

// ReportsDelivery signals the core auditor to skip RecordDelivery for
// this output — delivery accounting is handled by OutputMetrics in
// writeLoop.
func (o *AsyncOutput) ReportsDelivery() bool { return true }

// SetOutputMetrics receives the per-output metrics instance from
// outputconfig.Load when WithOutputMetrics is configured.
func (o *AsyncOutput) SetOutputMetrics(m audit.OutputMetrics) {
    o.outputMetrics.Store(&m)
}
```

## Receiving Per-Output Metrics

Outputs that want delivery metrics (drops, flushes, errors, retries,
queue depth) implement `OutputMetricsReceiver`:

```go
type OutputMetricsReceiver interface {
    SetOutputMetrics(m OutputMetrics)
}
```

### When It Is Called

`outputconfig.Load` calls `SetOutputMetrics` once per output after
all outputs are constructed, before `Load` returns. The output's
background goroutine may already be running at this point (started
in the output constructor). The `atomic.Pointer` storage pattern
ensures safe handoff: the goroutine checks for nil before using
`outputMetrics`, and `SetOutputMetrics` stores atomically. Because
`New` is not called until after `Load` returns, no `Write`
calls are made before `SetOutputMetrics` completes. This happens
only when the consumer passes `WithOutputMetrics(factory)` as a
load option:

```go
factory := func(outputType, outputName string) audit.OutputMetrics {
    return &myMetrics{
        drops: dropsVec.WithLabelValues(outputType, outputName),
        // ...
    }
}

result, err := outputconfig.Load(ctx, yamlData, taxonomy,
    outputconfig.WithOutputMetrics(factory),
)
```

Without `WithOutputMetrics`, no metrics are injected.

### The OutputMetrics Interface

The injected value satisfies `audit.OutputMetrics`:

```go
type OutputMetrics interface {
    RecordDrop()                              // event dropped (buffer full)
    RecordFlush(batchSize int, dur time.Duration) // batch/event delivered
    RecordError()                             // non-retryable delivery error
    RecordRetry(attempt int)                  // retry attempt (1-indexed)
    RecordQueueDepth(depth, capacity int)     // buffer pressure gauge
}
```

`RecordFlush` is the delivery-confirmed counterpart to the core
`Metrics.RecordDelivery("success")`. For `DeliveryReporter` outputs,
the core skips `RecordDelivery` entirely — `RecordFlush` is the only
signal that delivery succeeded.

### Storage Pattern

Store the `OutputMetrics` value using `atomic.Pointer` for safe
concurrent access between `SetOutputMetrics` (called during
`outputconfig.Load`) and the background write goroutine (which reads
it on every event):

```go
type MyOutput struct {
    outputMetrics atomic.Pointer[audit.OutputMetrics]
    // ...
}

func (o *MyOutput) SetOutputMetrics(m audit.OutputMetrics) {
    o.outputMetrics.Store(&m)
}

// In your write loop:
func (o *MyOutput) writeLoop() {
    // ...
    if omp := o.outputMetrics.Load(); omp != nil {
        (*omp).RecordFlush(1, elapsed)
    }
}
```

### Extension Interfaces

The `OutputMetrics` value MAY also implement output-specific extension
interfaces for metrics beyond the common five. Each output type can
detect extensions via type assertion in `SetOutputMetrics`:

```go
type MyOutput struct {
    outputMetrics atomic.Pointer[audit.OutputMetrics]
    extMetrics    atomic.Pointer[myExtMetrics] // output-specific extension
    // ...
}

type myExtMetrics interface {
    RecordReconnect(addr string, ok bool)
}

func (o *MyOutput) SetOutputMetrics(m audit.OutputMetrics) {
    o.outputMetrics.Store(&m)

    // Detect extension interface via type assertion.
    if em, ok := m.(myExtMetrics); ok {
        o.extMetrics.Store(&em)
    }
}
```

See `file.RotationRecorder` (`RecordRotation`) and
`syslog.ReconnectRecorder` (`RecordReconnect`) for built-in examples
of this pattern.

### Forward Compatibility

Consumers SHOULD embed `audit.NoOpOutputMetrics` in their
`OutputMetrics` implementation. New methods added to the interface
in future versions will be absorbed by the embedded no-op:

```go
type myMetrics struct {
    audit.NoOpOutputMetrics // forward compatibility
    drops prometheus.Counter
}

func (m *myMetrics) RecordDrop() { m.drops.Inc() }
```

## Reporting Delivery Outcomes

Async outputs that record delivery outcomes after actual I/O (not at
enqueue time) SHOULD implement `DeliveryReporter`:

```go
type DeliveryReporter interface {
    ReportsDelivery() bool
}
```

### What It Controls

When `ReportsDelivery()` returns `true`, the core auditor's post-write
logic skips `Metrics.RecordDelivery(outputName, audit.EventSuccess | audit.EventError)` and
`Metrics.RecordOutputError(outputName)` for that output. Delivery
accounting is left entirely to the output via `OutputMetrics`:

- `RecordFlush` replaces `Metrics.RecordDelivery(name, audit.EventSuccess)`
- `RecordError` replaces `Metrics.RecordDelivery(name, audit.EventError)` and
  `Metrics.RecordOutputError(name)`

**Panic exception:** if the output panics during `Write`, the core
logger calls `Metrics.RecordOutputError` regardless of
`ReportsDelivery()` — a panic means the output did not self-report.
`Metrics.RecordDelivery` is not called on the panic path for any output.

### Why It Exists

Without `DeliveryReporter`, the core logger calls
`RecordDelivery("success")` as soon as `Write` returns. For an async
output, `Write` returning means the event entered the buffer — not
that it was delivered. If the output also calls
`OutputMetrics.RecordFlush` after actual delivery, every event is
counted twice.

Implementing `DeliveryReporter` eliminates this double-counting.
For an async output that calls `RecordFlush` after actual delivery:

| | Without DeliveryReporter | With DeliveryReporter |
|---|---|---|
| Core calls `RecordDelivery` | Yes (at enqueue) | No |
| Output calls `RecordFlush` | Yes (at delivery) | Yes (at delivery) |
| Result | Double-counted | Correct |

### Implementation

For async outputs, always return `true`:

```go
func (o *AsyncOutput) ReportsDelivery() bool { return true }
```

### WrapOutput Transparency

`WrapOutput` returns a `namedOutput` that has a `ReportsDelivery()`
method. When the inner output implements `DeliveryReporter`, the
wrapper forwards; when it does not, `ReportsDelivery()` returns
`false`. Custom factories MUST use `WrapOutput` to preserve this
forwarding for all optional interfaces:

```go
func init() {
    audit.RegisterOutputFactory("my-output", func(name string, rawConfig []byte, coreMetrics audit.Metrics, logger *slog.Logger, fctx audit.FrameworkContext) (audit.Output, error) {
        inner := &MyAsyncOutput{/* ... */}
        return audit.WrapOutput(inner, name), nil
    })
}
```

## Thread Safety

`Write` and `WriteWithMetadata` are called only from the single drain
goroutine — they are never called concurrently with each other.

For async outputs, `Write` only touches the internal channel (a
non-blocking send) and the `closed` atomic flag — the actual I/O
happens in a separate background goroutine that the output owns. The
async skeleton above is safe without a `Write`-level mutex because
`Write` does not access any shared mutable state beyond the channel
and atomic flag, which are each independently safe. The `sync.Mutex`
in `Close()` guards against concurrent `Close` calls, not `Write`.

`Close()` may be called from a different goroutine while a `Write` is
still in progress (if the drain timeout expires during shutdown). For
synchronous outputs, use a `sync.Mutex` to protect against
`Write`/`Close` races if your output holds state that both methods
access.

## Further Reading

- [Async Delivery](async-delivery.md) — two-level buffering, memory sizing, tuning
- [Metrics and Monitoring](metrics-monitoring.md) — `OutputMetrics` wiring, event accounting
- [Output Types](outputs.md) — built-in outputs and their delivery models
- [Output Configuration YAML](output-configuration.md) — YAML reference for all outputs
