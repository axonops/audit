[← Back to examples](../README.md)

> **Previous:** [15 — TLS Policy](../15-tls-policy/) |
> **Next:** [17 — CRUD API](../17-crud-api/)

# Example 16: Buffering and Backpressure

Demonstrates the two-level buffering architecture that sits between
your `AuditEvent()` call and the final output destinations. Understanding
this architecture is essential for tuning performance and diagnosing
event drops in production.

## What You'll Learn

- Why go-audit has two levels of buffering and how they interact
- What `ErrBufferFull` means and when it fires (Level 1)
- What `RecordWebhookDrop` / `RecordLokiDrop` mean (Level 2)
- The difference between `buffer_size` and `batch_size`
- Why a slow synchronous output blocks all outputs
- How to tune buffer sizes for your workload

## Prerequisites

- Completed: [Multi-Output](../09-multi-output/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Simple 2-event taxonomy |
| `outputs.yaml` | Core buffer (size 5) + file output + webhook output (unreachable endpoint) |
| `audit_generated.go` | Generated typed builders |
| `main.go` | Emits events in a burst to trigger both levels of backpressure |

## Key Concepts

### The Two-Level Pipeline

```
                    Level 1                              Level 2
                    ───────                              ───────
AuditEvent() ──► core channel ──► drain goroutine ─┬──► File.Write()                  [synchronous]
                 (buffer_size)     (single)        │
                                                   └──► Webhook.Write() ──► batchLoop ──► HTTP POST
                                                        (buffer_size)
```

**Level 1** is the core logger buffer — a Go channel between
`AuditEvent()` and the drain goroutine. When full, `AuditEvent()`
returns `ErrBufferFull` and the event is lost.

**Level 2** exists only in async outputs (webhook, Loki). These
outputs have their own internal channel and a background goroutine
that accumulates events into batches before sending HTTP requests.
When their buffer fills, events are dropped silently with metrics.

Synchronous outputs (file, syslog, stdout) have no Level 2 buffer.
They write directly from the drain goroutine.

### `buffer_size` vs `batch_size`

Two different configs that mean different things:

| Config | Where | Default | What It Controls |
|--------|-------|---------|------------------|
| `logger.buffer_size` | YAML `logger:` section | 10,000 | Level 1 core channel capacity |
| output `buffer_size` | Per webhook/Loki output | 10,000 | Level 2 per-output channel capacity |
| output `batch_size` | Per webhook/Loki output | 100 | Events grouped per HTTP POST |

`batch_size` is **not** `buffer_size`. With defaults (`buffer_size:
10000`, `batch_size: 100`), up to 100 batches of events can queue
before Level 2 drops begin.

### Why a Slow Synchronous Output Blocks Everything

The drain goroutine delivers to outputs **sequentially**. If a syslog
TCP write blocks for 30 seconds (server unreachable), no events reach
file, webhook, or Loki during that time. The file output in this
example is fast (local disk), but in production a slow syslog server
would cause the core buffer to fill and `ErrBufferFull` to fire.

Async outputs (webhook, Loki) do not block the drain goroutine —
they copy events into their own buffer and return immediately.

### What This Example Demonstrates

1. **Core buffer fills** — `buffer_size: 5` in `outputs.yaml` means
   only 5 events fit in the channel. Emitting 20 events in a tight
   loop causes 14+ `ErrBufferFull` returns.

2. **Webhook drops** — the webhook points at `http://localhost:19999`
   where nothing is listening. Delivery fails, retries exhaust, and
   the batch is dropped. The `slog.Warn` and `slog.Error` diagnostics
   on stderr show this happening.

3. **File output is unaffected** — the file output writes
   synchronously and succeeds for every event that made it through
   the core buffer. Webhook failures do not affect file delivery.

### Output Configuration

```yaml
# Level 1 — core buffer
logger:
  buffer_size: 5           # Tiny buffer to trigger ErrBufferFull
  drain_timeout: "2s"

outputs:
  # Synchronous output — no internal buffer
  audit_file:
    type: file
    file:
      path: "./audit-buffering-demo.log"

  # Async output — has its own buffer and batch goroutine
  webhook_demo:
    type: webhook
    webhook:
      url: "http://localhost:19999/audit"     # Nothing listening
      allow_insecure_http: true
      allow_private_ranges: true
      buffer_size: 10        # Level 2 buffer
      batch_size: 5          # Events per HTTP POST
      flush_interval: "1s"
      timeout: "1s"
      max_retries: 1
```

## Run It

```bash
go run .
```

## Expected Output

```
INFO audit: logger created buffer_size=5 drain_timeout=2s validation_mode=strict outputs=2
--- Level 1: Core Buffer (buffer_size: 5) ---
Emitting 20 events in a tight loop...
WARN audit: buffer full, events dropped dropped=1 buffer_size=5
  Delivered: 6, Dropped (ErrBufferFull): 14
  → Core buffer was full. In production, increase logger.buffer_size
    or investigate slow synchronous outputs blocking the drain goroutine.

--- Level 2: Webhook Buffer (buffer_size: 10) ---
The webhook points at an unreachable endpoint.
Watch stderr for drop warnings from the webhook output.
The file output (synchronous) is unaffected.
WARN audit: webhook retryable error attempt=1 max_retries=1 error="..."
ERROR audit: webhook retries exhausted, dropping batch batch_size=5 max_retries=1
# ... additional webhook errors for remaining events (partial batch flush at shutdown)

--- Buffering Architecture Summary ---
  (architecture diagram and tuning guidance)

INFO audit: shutdown started
INFO audit: shutdown complete duration=...
```

The `INFO` and `WARN` lines are lifecycle diagnostics on stderr.
The exact number of delivered vs dropped events may vary by machine
speed — the key point is that `ErrBufferFull` fires when the core
buffer is full, and the webhook drops events independently without
affecting the file output.

## Tuning for Production

| Symptom | Fix |
|---------|-----|
| `ErrBufferFull` from `AuditEvent()` | Increase `logger.buffer_size` (default 10,000, max 1,000,000) |
| `RecordWebhookDrop` / `RecordLokiDrop` | Increase output `buffer_size`, decrease `flush_interval` |
| High event latency | Decrease `flush_interval` or `batch_size` |
| Excessive memory | Decrease `buffer_size` (each 10,000 events ≈ 5 MB with typical events) |

## Further Reading

- [Two-Level Buffering](../../docs/async-delivery.md#two-level-buffering) — complete architecture reference
- [Output Types](../../docs/outputs.md#-buffering-and-delivery-model) — sync vs async comparison table
- [Webhook Output](../../docs/webhook-output.md#buffering-architecture) — webhook buffering details
- [Loki Output](../../docs/loki-output.md#buffering-architecture) — Loki buffering details
