# Performance — Fast Path, Slow Path, and the Ownership Contract

This document describes the audit pipeline's allocation behaviour, the two
event-construction paths, and how the library reaches **zero allocations
per event on the drain side** for the common case.

It is required reading for anyone:

- benchmarking the library against alternatives,
- writing a custom output and trying to understand the byte-retention contract,
- tuning a high-throughput deployment,
- reviewing changes to the drain pipeline.

For the full benchmark table see [`BENCHMARKS.md`](../BENCHMARKS.md).

---

## TL;DR

| Construction path        | Drain allocs/op | Notes                                                 |
|--------------------------|-----------------|-------------------------------------------------------|
| Generated builder (fast) | **0**           | `audit-gen` output, satisfies the `FieldsDonor` interface |
| `NewEvent` (slow)        | 1 (defensive copy) + value boxing | Consumer escape hatch for map-based events            |

Numbers from `BenchmarkAudit_FastPath_PipelineOnly` (donor outside loop,
`internal/testhelper.NoopOutput`): **0 allocs/op @ ~440 ns/op** on AMD
Ryzen 9 7950X / Go 1.26.

---

## The two paths

Audit events enter the pipeline via [`Auditor.AuditEvent`]. Internally the
auditor inspects the concrete type:

```
                       AuditEvent(evt Event)
                                |
                +---------------+-----------------+
                |                                 |
   evt implements FieldsDonor?           plain Event (default)
                |                                 |
        donate Fields map                   defensive copy of
        (no clone)                          Fields into a pooled
                |                           map (slow path)
                +---------------+-----------------+
                                |
                  drainScratch buffer-lease pipeline
                                |
              format → in-place post-fields → output.Write
                                |
                  pool returns in processEntry's defer
```

### Fast path — `FieldsDonor`

Generated builders from `cmd/audit-gen` emit a `donateFields()` method
that nobody outside the audit-gen toolchain can satisfy (the method is
**unexported** — `package audit` is the only place the sentinel is
visible). When the auditor sees `evt.(FieldsDonor)`, it skips the
defensive `Fields` map copy because it knows the builder will not mutate
or retain the map after `AuditEvent` returns.

The single per-event allocation that remains for the fast path is the
**caller-side allocation of the builder + its `Fields` literal**. That
allocation is in consumer code; the audit pipeline contributes zero
allocations on the drain side after warm-up. The v1.1 follow-up
([#660](https://github.com/axonops/audit/issues/660)) introduces a
`BuiltEvent` typed-field interface that eliminates even that caller-side
cost via pooled builders + typed `[]Field` slices.

The contract the donor commits to is documented on `FieldsDonor`:

> Implementers MUST NOT mutate or retain the returned Fields after
> Event.Fields() is called by the auditor. Re-using the same Event
> instance for a second AuditEvent call is undefined behaviour.

If you are writing a third-party `Event` type and you do not control a
code generator that emits the sentinel, you stay on the slow path. There
is no way to opt in from outside `package audit` — by design.

### Slow path — `NewEvent` and `NewEventKV`

Most consumers have a `map[string]any` already (e.g. fields populated
from request data, struct serialisation, or middleware). `NewEvent` is
the documented escape hatch:

```go
auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
    "outcome":  "success",
    "actor_id": "alice",
}))
```

The auditor cannot trust the caller's map — it might be reused, mutated,
or shared. So it clones the map into a pooled destination map and works
from the clone. This adds 1 allocation per event (the destination map)
plus boxing for any non-string values.

The slow path still benefits from every other W2 optimisation: the
formatter buffer is leased from the pool; sorted-key slices are pooled;
per-output post-fields are appended in place into the scratch buffer.

> **Dynamic event type but throughput matters?** If your event type is
> known at startup (from configuration, a database, or a plugin
> registry) but not at compile time, use
> [`EventHandle.Audit(fields)`](https://pkg.go.dev/github.com/axonops/audit#EventHandle.Audit)
> instead of `NewEvent`. Obtain the handle once via
> [`Auditor.Handle`](https://pkg.go.dev/github.com/axonops/audit#Auditor.Handle)
> or [`Auditor.MustHandle`](https://pkg.go.dev/github.com/axonops/audit#Auditor.MustHandle)
> at startup and cache it. `EventHandle.Audit` bypasses the `basicEvent`
> heap allocation that `NewEvent` incurs via interface escape — after
> `sync.Pool` warm-up the defensive `Fields` copy is also recycled, so
> the amortised cost is `0 allocs/op` end-to-end. See the
> `BenchmarkAudit_ViaHandle_vs_NewEvent` numbers in
> [`BENCHMARKS.md`](../BENCHMARKS.md#emission-path-comparison).

---

## The drain-side zero-copy pipeline

Once the event reaches `processEntry` (one event per drain-goroutine
call), the W2 pipeline is identical for both paths:

1. **Format cache acquires a pool-leased `*bytes.Buffer`** the first
   time a unique formatter is invoked for the event. The buffer holds
   the JSON or CEF wire bytes; the cache stores `buf.Bytes()` aliasing
   the leased buffer's backing array.

2. **Per-output category + HMAC assembly** runs inside the per-event
   `postBuf` (a separate pool-leased buffer). The base bytes from the
   format cache are copied into `postBuf` once per output; subsequent
   `event_category` and HMAC field appends mutate `postBuf` in place
   via `appendPostFieldJSONInto` / `appendPostFieldCEFInto`. Truncate-
   and-restore semantics on the trailing `}\n` (JSON) or `\n` (CEF)
   keep the operation O(field-bytes) per append.

3. **Outputs receive `postBuf.Bytes()`**. Per the [`Output.Write`
   contract](../output.go), implementations MUST NOT retain the data
   past the call. All first-party outputs already copy on enqueue.

4. **`processEntry`'s defer chain runs `formatCache.release()`** which
   returns every leased buffer to its pool. Buffers exceeding 64 KiB
   capacity are dropped (let GC reclaim) to bound pool memory. The
   defensive `clear()` zeros the entire backing array on Put — this
   defends against future read-past-len bugs that could leak prior-event
   bytes to a misbehaving consumer.

### What the drain path does NOT allocate

- No `make([]byte, …)` for the formatter output. Pre-W2: 1 alloc per
  event per unique formatter.
- No `make([]byte, …)` per `AppendPostField` call (event_category +
  HMAC's `_hmac_v` + HMAC's `_hmac`). Pre-W2: up to 3 allocs per output
  per HMAC-enabled fan-out.
- No `make([]string, …)` for sorted field keys when no extras are
  present. Pre-W2: variable.

---

## Per-output sensitivity-label exclusion is exempt from the buffer lease

When an output has `excludeLabels` configured, its serialisation differs
from every other output (different per-output bytes). The format cache
cannot be shared in that case, so `formatWithExclusion` stays on the
public `Formatter.Format` path with a defensive copy. This is a
deliberate carve-out — see the security review of #497 for the rationale
(short version: trying to fold per-output label-stripped output into a
shared buffer creates an aliasing hazard that no amount of locking
fixes).

If you are deploying with sensitivity-label exclusion and observe
higher drain allocations, that's expected and correct.

---

## The `Output.Write` retention contract

Pre-W2, the byte slice handed to `Output.Write` was `make`d fresh per
event. Outputs could retain it indefinitely and nothing would notice.

Post-W2, the bytes alias a pool-leased buffer. After
`processEntry`'s defer returns the buffer to the pool, the backing
array is zeroed and reused for the next event.

The contract is now explicit on `Output.Write`:

> The library MAY reuse data's underlying array after Write returns.
> Implementations MUST NOT retain data, or any slice that aliases its
> backing array, past the Write call. If the bytes are needed beyond
> the call (for example, to enqueue onto an asynchronous worker
> channel), implementations MUST copy them — for example with
> `append([]byte(nil), data...)`. All first-party async outputs (file,
> syslog, webhook, loki) already copy on enqueue.

This contract is **load-bearing for HMAC integrity**: an output that
retains bytes and reads them later (after the buffer is recycled) would
present a different byte sequence than the one HMAC was computed over,
breaking authentication on the wire.

The defensive `clear()` on pool-Put plus per-buffer in-place truncation
turn any contract violation into observable garbled bytes (zeros, partial
events, never silently-impersonated foreign events). See
`processentry_zero_copy_test.go` for the regression coverage that pins
this property.

### How to write a third-party output that honours the contract

If you write an output that delivers bytes synchronously (the bytes
have been written before `Write` returns), no copy needed:

```go
func (o *MyOutput) Write(data []byte) error {
    _, err := o.conn.Write(data)
    return err
}
```

If you write an output that delivers asynchronously, copy first and
record drops via [`OutputMetrics.RecordDrop`] — do **not** return
[`audit.ErrQueueFull`] from `Output.Write`. That sentinel is reserved
for the core auditor's intake queue (`Auditor.AuditEvent` → channel
send); a third-party output returning it tells the drain goroutine
the wrong thing and the drop will be double-counted. See
[`docs/writing-custom-outputs.md`](writing-custom-outputs.md) for the
full third-party output contract.

```go
func (o *MyOutput) Write(data []byte) error {
    // Defensive copy — required by the Output.Write contract.
    cp := append([]byte(nil), data...)
    select {
    case o.queue <- cp:
        return nil
    default:
        // Buffer full — drop and record via OutputMetrics.
        if om := o.outputMetrics.Load(); om != nil {
            (*om).RecordDrop()
        }
        return nil // NOT ErrQueueFull
    }
}
```

[`OutputMetrics.RecordDrop`]: https://pkg.go.dev/github.com/axonops/audit#OutputMetrics
[`audit.ErrQueueFull`]: https://pkg.go.dev/github.com/axonops/audit#ErrQueueFull

---

## Pool sizing and memory hygiene

`jsonBufPool` and `cefBufPool` accept buffers up to **64 KiB** capacity.
Buffers that grew beyond 64 KiB serving an outlier event are not
re-pooled — let GC reclaim them. This bounds the pool's working set
under pathological events (a 1 MiB log message, a stack trace, a query
text) without crippling the typical ~400-byte event.

The sorted-key pool (`sortedKeysPool`) similarly caps return at
`maxPooledKeysCap` (64 entries). Events with > 64 fields are
pathological enough that letting them allocate fresh keeps the pool
representative of the normal case.

`sync.Pool` evicts on every GC cycle, so under sustained load the pool
size stabilises around the working set, and under spike-then-quiet the
next GC drops everything. This is by design — the pool is an
optimisation, not a memory bank.

---

## Benchmark methodology

Run `make bench` to capture the full table; `make bench-compare` runs
benchstat against the committed `bench-baseline.txt`.

The interesting benchmarks for the drain pipeline are:

- `BenchmarkAudit_FastPath_PipelineOnly` — donor constructed once
  outside the loop. This is the cleanest measurement of pipeline cost
  alone. **0 allocs/op** post-W2.
- `BenchmarkAudit_FastPath_EndToEnd` — donor constructed inside the
  loop. Realistic per-call cost; the remaining allocs are caller-side
  (`Fields{}` literal + `any`-boxing per non-string field). The v1.1
  `BuiltEvent` work in #660 addresses these.
- `BenchmarkAudit_FastPath_FanOut4_NoopOutputs` — fan-out to 4 outputs
  sharing one formatter. Format cache hits 3 times; per-output marginal
  cost is the post-field assembly + write. **0 allocs/op** post-W2.
- `BenchmarkAudit_FastPath_WithHMAC_Noop` — HMAC enabled, single
  output. Confirms the in-place HMAC append (W2.4) does not allocate.
  **0 allocs/op** post-W2.
- `BenchmarkAudit_FastPath_Parallel` — `RunParallel` + 32 cores.
  Catches lock-contention regressions; ns/op MUST NOT scale linearly
  with GOMAXPROCS.
- `BenchmarkAudit_RealisticFields` — `NewEvent` slow path, 10 fields,
  MockOutput. Pre-W2: 2 allocs/op, 670 B/op. Post-W2: 1 alloc/op,
  320 B/op. The remaining alloc is the slow path's defensive map clone.

Use the `internal/testhelper.NoopOutput` for pipeline benchmarks — it
neither copies nor inspects bytes (just an atomic counter). Using
`MockOutput` contaminates the measurement with the per-call defensive
copy and mutex acquisition.

---

## What is NOT addressed by W2

- The caller-side allocations: building the builder struct, building
  the `Fields{}` literal, boxing non-string values into `any`. These
  are tackled by [#660](https://github.com/axonops/audit/issues/660)
  (BuiltEvent typed-field interface for v1.1).
- The defensive copy on the slow path. This is the documented contract
  of `NewEvent`; consumers who want zero allocations should generate
  builders.
- Per-output sensitivity-label exclusion. This stays on the
  defensive-copy path by design (see above).
- Output-side allocations. Each first-party output makes its own
  trade-offs (file batching, syslog reconnection, webhook retry, loki
  stream label cardinality). See each output's docs.

---

## See also

- [`docs/adr/0001-fields-ownership-contract.md`](adr/0001-fields-ownership-contract.md) — the FieldsDonor design rationale
- [`BENCHMARKS.md`](../BENCHMARKS.md) — the full benchmark table
- [`docs/code-generation.md`](code-generation.md) — generated builders and how they participate in the fast path
- [`docs/hmac-integrity.md`](hmac-integrity.md) — HMAC ordering and how the in-place assembly preserves authentication
- [`docs/writing-custom-outputs.md`](writing-custom-outputs.md) — full Output contract including the no-retention rule
