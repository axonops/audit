[&larr; Back to README](../README.md)

# Async Delivery and Pipeline Architecture

## How Events Flow

```
AuditEvent(event)                           drain goroutine
  ├── validate fields                       ──────────────
  ├── check category enabled                reads from channel
  └── enqueue to buffered channel ─────────►  ├── set timestamp
                                              ├── serialize (JSON or CEF)
                                              └── fan-out to each output
                                                   ├── per-output route filter
                                                   ├── per-output sensitivity filter
                                                   └── Output.Write(bytes)
```

## Why Async?

Audit logging must not slow down the operations it audits. If writing
to a syslog server takes 5ms, a synchronous audit call would add 5ms
to every request. The async pipeline decouples event production from
delivery:

- `AuditEvent()` validates and enqueues — sub-microsecond
- The drain goroutine handles serialisation and delivery in the background
- Your application continues immediately after the call returns

## Buffering and Backpressure

Events are held in a buffered channel with configurable capacity:

| Config Field | Default | Max | Purpose |
|-------------|---------|-----|---------|
| `BufferSize` | 10,000 | 1,000,000 | Channel capacity |
| `DrainTimeout` | 5 seconds | 60 seconds | Shutdown flush deadline |

When the buffer is full, `AuditEvent()` returns `ErrBufferFull`
immediately and the drop is recorded via `Metrics.RecordBufferDrop()`.
The event is lost — it is not retried.

### Sizing the Buffer

The right buffer size depends on your event volume and output latency:

- **Low volume** (< 100 events/sec) — default 10,000 is more than enough
- **High volume** (1,000+ events/sec) — increase if you see buffer drops
- **Slow outputs** (high-latency webhooks) — larger buffer absorbs spikes

Monitor `RecordBufferDrop()` — if it fires, your buffer is too small
or your outputs are too slow.

## Delivery Guarantee

**At-most-once within a process lifetime.**

An event is either delivered to all outputs or lost. Events can be
lost in two scenarios:

1. **Buffer full** — `AuditEvent()` returns `ErrBufferFull`
2. **Shutdown timeout** — events still in the buffer when `Close()`'s
   drain timeout expires are dropped with a warning

Events are never duplicated at the pipeline level. (The webhook output
has its own at-least-once retry semantics for HTTP delivery — see
[Outputs](outputs.md).)

## Graceful Shutdown

`Logger.Close()` MUST be called when the logger is no longer needed:

1. Signals the drain goroutine to stop accepting new events
2. Flushes pending events from the buffer (up to `DrainTimeout`)
3. Closes all outputs in sequence
4. Returns any close errors

Events still in the buffer when the drain timeout expires are lost.
`Close()` is idempotent — calling it multiple times is safe.

```go
logger, err := audit.NewLogger(cfg, opts...)
defer func() {
    if err := logger.Close(); err != nil {
        log.Printf("audit close: %v", err)
    }
}()
```

**Failing to call Close leaks the drain goroutine and loses all
buffered events.**

## Thread Safety

- `AuditEvent()` is safe for concurrent use from any number of goroutines
- Category enable/disable uses lock-free reads on the hot path
- The single drain goroutine means outputs do not need to be thread-safe
- `Close()` is idempotent via `sync.Once`

## Lifecycle Events

The library supports lifecycle events that create a tamper-evident
audit trail:

- **Startup event** — emitted via `logger.EmitStartup(fields)`
- **Shutdown event** — emitted automatically by `logger.Close()`

If a shutdown event is missing from the audit trail, the application
crashed or was killed without graceful shutdown.

## Further Reading

- [Metrics and Monitoring](metrics-monitoring.md) — tracking buffer drops and output failures
- [Outputs](outputs.md) — output types and fan-out architecture
- [Architecture](../ARCHITECTURE.md) — pipeline implementation details
