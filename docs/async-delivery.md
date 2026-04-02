[&larr; Back to README](../README.md)

# Async Delivery and Pipeline Architecture

- [How Events Flow](#how-events-flow)
- [Why Async?](#why-async)
- [Buffering and Backpressure](#buffering-and-backpressure)
- [Delivery Guarantee](#delivery-guarantee)
- [Graceful Shutdown](#graceful-shutdown)
- [Thread Safety](#thread-safety)

## 🔧 How Events Flow

```
AuditEvent(event)
  ├── validate fields against taxonomy
  ├── check category enabled (DisableCategory can disable at runtime)
  └── enqueue to buffered channel ──► drain goroutine (reads continuously)
                                        ├── set timestamp
                                        ├── serialize (JSON or CEF)
                                        └── fan-out to each output
                                             ├── per-output route filter
                                             ├── per-output sensitivity filter
                                             └── Output.Write(bytes)
```

## ❓ Why Async?

Audit logging must not slow down the operations it audits. If writing
to a syslog server takes 5ms, a synchronous audit call would add 5ms
to every request. The async pipeline decouples event production from
delivery:

- `AuditEvent()` validates and enqueues — sub-microsecond
- A single drain goroutine reads events from the channel **continuously** as they arrive — there is no periodic flush interval
- Your application continues immediately after the call returns

### Is Async Acceptable for Compliance?

Yes. Asynchronous audit delivery is standard practice across the
industry:

- **Linux Audit (auditd)** writes events to a kernel ring buffer and
  drains asynchronously to disk — the syscall does not block on I/O
- **Windows Event Log** uses an asynchronous ETW (Event Tracing for
  Windows) pipeline
- **Cloud platforms** (AWS CloudTrail, GCP Cloud Audit Logs, Azure
  Activity Log) all deliver events asynchronously with eventual
  consistency guarantees

The key is not synchronous delivery — it is **completeness monitoring**.
go-audit provides this through the [Metrics interface](metrics-monitoring.md):

- `RecordBufferDrop()` fires if an event is lost due to backpressure
- `RecordOutputError()` fires if an output fails to write
- `RecordEvent(output, "error")` tracks delivery failures per output

Wire these to your monitoring system and alert on any non-zero buffer
drops or output errors. This gives you the same assurance as
synchronous delivery: if an event is lost, you know about it.

The library is not a database — it is a pipeline component within
your application process. Synchronous audit logging would mean your
HTTP handler blocks on syslog TCP writes, which creates cascading
failures when the syslog server is slow or unreachable. Async delivery
with monitoring is both safer and more reliable in practice.

## 📦 Buffering and Backpressure

Events are held in a buffered channel. The drain goroutine reads from
this channel continuously — events are processed as fast as the
outputs can write them.

### Configuration

Buffer and drain settings are configured in the `logger:` section of
your output YAML:

```yaml
logger:
  buffer_size: 50000         # default: 10,000, max: 1,000,000
  drain_timeout: "30s"       # default: "5s", max: "60s"
```

Or programmatically via the `Config` struct:

```go
logger, err := audit.NewLogger(
    audit.Config{
        Version:      1,
        Enabled:      true,
        BufferSize:   50_000,
        DrainTimeout: 30 * time.Second,
    },
    audit.WithTaxonomy(tax),
    audit.WithOutputs(out),
)
```

When using `outputconfig.Load`, the parsed `result.Config` contains
these values from your YAML — pass it directly to `NewLogger`.

| Field | Default | Max | What It Does |
|-------|---------|-----|-------------|
| `BufferSize` | 10,000 | 1,000,000 | Capacity of the async channel. When full, `AuditEvent()` returns `ErrBufferFull` and the event is lost. |
| `DrainTimeout` | 5 seconds | 60 seconds | How long `Close()` waits for remaining events to flush before giving up. Events still in the buffer after this timeout are lost. |

**Note:** `DrainTimeout` only applies during shutdown (when you call
`Close()`). During normal operation, the drain goroutine processes
events continuously with no timeout.

### Sizing the Buffer

- **Low volume** (< 100 events/sec) — default 10,000 is more than enough
- **High volume** (1,000+ events/sec) — increase if you see buffer drops
- **Slow outputs** (high-latency webhooks) — larger buffer absorbs spikes

Monitor `RecordBufferDrop()` — if it fires, your buffer is too small
or your outputs are too slow.

## 📤 Delivery Guarantee

**At-most-once within a process lifetime.**

An event is either delivered to all outputs or lost. Events can be
lost in two scenarios:

1. **Buffer full** — `AuditEvent()` returns `ErrBufferFull`
2. **Shutdown timeout** — events still in the buffer when `Close()`'s
   drain timeout expires are dropped with a warning

Events are never duplicated at the pipeline level. (The webhook output
has its own at-least-once retry semantics for HTTP delivery — see
[Outputs](outputs.md).)

## 🛑 Graceful Shutdown

`Logger.Close()` MUST be called when the logger is no longer needed:

1. Signals the drain goroutine to stop accepting new events
2. Flushes pending events from the buffer (up to `DrainTimeout`)
3. Closes all outputs in sequence
4. Returns any close errors

**Failing to call Close leaks the drain goroutine and loses all
buffered events.**

### Where to Call Close

In a typical Go HTTP server, use signal handling to ensure `Close()`
is called before the process exits:

```go
func main() {
    logger, err := audit.NewLogger(cfg, opts...)
    if err != nil {
        log.Fatal(err)
    }

    srv := &http.Server{Addr: ":8080", Handler: router}

    // Start server in background.
    go func() {
        if err := srv.ListenAndServe(); err != http.ErrServerClosed {
            log.Printf("http: %v", err)
        }
    }()

    // Wait for SIGINT or SIGTERM.
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    // 1. Stop accepting new HTTP requests.
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    srv.Shutdown(ctx)

    // 2. Close the logger — flushes all pending audit events.
    if err := logger.Close(); err != nil {
        log.Printf("audit close: %v", err)
    }

    log.Println("shutdown complete")
}
```

**Key ordering:** Stop the HTTP server first (so no new audit events
are generated), then close the logger (so all pending events flush).

For simpler applications without an HTTP server, `defer` works:

```go
func main() {
    logger, err := audit.NewLogger(cfg, opts...)
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        if err := logger.Close(); err != nil {
            log.Printf("audit close: %v", err)
        }
    }()

    // ... your application logic ...
}
```

See [Progressive Example: CRUD API](../examples/10-crud-api/) for a
complete working example with signal handling.

## 🔒 Thread Safety

- `AuditEvent()` is safe for concurrent use from any number of goroutines
- Category enable/disable uses lock-free reads on the hot path
- The single drain goroutine means outputs do not need to be thread-safe
- `Close()` is idempotent via `sync.Once`

## 📚 Further Reading

- [Metrics and Monitoring](metrics-monitoring.md) — tracking buffer drops and output failures
- [Outputs](outputs.md) — output types and fan-out architecture
- [Architecture](../ARCHITECTURE.md) — pipeline implementation details
