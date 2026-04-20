# Benchmark Results

This file tracks benchmark results over time to detect performance regressions and measure optimisation impact.

## How to Use

```bash
make bench           # Run benchmarks, save to bench.txt
make bench-save      # Run + save as bench-baseline.txt (committed)
make bench-compare   # Run + compare against bench-baseline.txt via benchstat
```

The CI pipeline runs `make bench` on every PR and compares against `bench-baseline.txt` when present.

---

## Current Baseline

**Date:** 2026-04-19
**Commit:** feature/497-fieldsdonor-fast-path (post-W2 zero-copy drain)
**Go:** 1.26+
**CPU:** AMD Ryzen 9 7950X 16-Core (32 threads)
**OS:** Linux 6.14.0
**Samples:** `count=5` per benchmark; benchstat confidence requires ≥6 so the current report is indicative (`± ∞`). Compare rather than read absolutes.

> **#497 W2 zero-copy drain landed in this baseline.** Most Audit-path
> benchmarks dropped from 2 → 1 allocs/op with byte-allocation
> reductions of 40–55 %. The donor fast path (generated builders that
> satisfy `FieldsDonor`) reaches 0 allocs/op on the drain side end-to-
> end. See [`docs/performance.md`](docs/performance.md) for the full
> ownership model and methodology.

### Core Audit Path

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit | 378 | 182 | **1** | 3 fields; W2 dropped 1 alloc + 142 B/op (prior baseline: 2 allocs/op, 324 B/op) |
| Audit_RealisticFields | 810 | 330 | **1** | 10 fields; W2 dropped 1 alloc + 340 B/op (prior baseline: 2 allocs/op, 670 B/op) |
| Audit_Parallel | 64 | 24 | 1 | GOMAXPROCS goroutines, per-op amortised |
| AuditDisabledCategory | 299 | 154 | 1 | Category disabled; drain skips write |
| Audit_EndToEnd | 391 | 189 | **1** | W2 dropped 1 alloc + 140 B/op |
| AuditDisabledAuditor | 18 | 24 | 1 | WithDisabled auditor — early return |

### Fan-Out (multi-output)

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| FanOut_SharedFormatter | 370 | 335 | **1** | 3 outputs, same formatter (W2: -1 alloc, -130 B/op) |
| FanOut_MixedFormatters | 346 | 230 | **1** | 3 outputs, 2 formatters (W2: -1 alloc, -115 B/op) |
| FanOut_FilteredOutputs | 362 | 255 | **1** | 3 outputs, 1 filtered (W2: -1 alloc, -150 B/op) |
| FanOut_5Outputs | 344 | 385 | 1-2 | 5 outputs, same formatter (W2 typical: 1 alloc) |

### HMAC Pipeline

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit_WithHMAC | 358 | 172 | **1** | Full Audit path with HMAC-SHA-256 appended; W2 dropped 1 alloc + 170 B/op (50 % reduction) |
| HMAC_SHA256_SmallEvent | 475 | 640 | 8 | Direct ComputeHMAC on small payload |
| HMAC_SHA256_LargeEvent | 1247 | 640 | 8 | Direct ComputeHMAC on large payload |
| HMAC_SHA512_SmallEvent | 1114 | 1120 | 8 | SHA-512 variant on small payload |

### Post-Serialisation Append

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| AppendPostFields_JSON | 88 | 160 | 1 | writeJSONString + pooled buffer |
| AppendPostFields_CEF | 57 | 128 | 1 | cefEscapeExtValue direct write |
| AppendPostFields_Disabled | 1.3 | 0 | 0 | nil fields fast path |

### Caller-Side Helpers

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| NewEventKV | 124 | 360 | 2 | slog-style event construction |
| FilterCheck | 16 | 0 | 0 | isEnabled lock-free (syncmap) |

### Emission-Path Comparison

Same auditor, same taxonomy, same `Fields` literal — what does the
caller-side choice cost? `NoopOutput` isolates the emission path by
removing output-side work. See `BenchmarkAudit_ViaHandle_vs_NewEvent`.

| Emission path | ns/op | B/op | allocs/op | Notes |
|---------------|------:|-----:|----------:|-------|
| `Auditor.AuditEvent(NewEvent(...))` | ~400 | 24 | **1** | One `basicEvent` escapes through the `Event` interface return |
| `EventHandle.Audit(fields)` | ~369 | **0** | **0** | No interface wrapping; defensive `Fields` copy recycles from `sync.Pool` after warm-up |

Observation: `EventHandle.Audit` eliminates the single remaining
caller-side allocation on the dynamic-event-type path (−1 alloc/op,
−24 B/op, ~8 % wall-clock). For event types known at compile time,
generated typed builders satisfying `FieldsDonor` additionally skip
the defensive `Fields` map copy — that is the zero-allocation
drain-side fast path, benchmarked as `BenchmarkAudit_FastPath_FanOut4_NoopOutputs`.

### Formatters

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| JSONFormatter_Format | 349 | 176 | 1 | 4 fields, buffer pooled, writeJSONString |
| JSONFormatter_Format_LargeEvent | 1208 | 640 | 1 | 20 fields |
| CEFFormatter_Format | 380 | 160 | 1 | 4 fields, buffer pooled, single-pass escape |
| CEFFormatter_Format_LargeEvent | 1170 | 577 | **1** | 20 fields; #496 dropped 3 → 1 allocs/op via in-place appendFormatFieldValue + writeEscapedExtValueString |
| CEFFormatter_Format_LargeEvent_Escaping | 2120 | 1518 | 4 | 20 fields, every value carries a CEF metacharacter; informational — additional allocs reflect the per-event `reserved` map + extra-field routing (out of #496 scope) |
| CEFFormatter_Format_Numeric | 1284 | 747 | 4 | 10 numeric fields (int/int64/uint64/float64/float32); informational — same extra-field routing story as _Escaping |
| CEFFormatter_Format_Parallel | 250 | 576 | 1 | 20 fields @ GOMAXPROCS; sub-linear scaling confirmed |
| FormatJSON_WithConfigFields | 443 | 240 | 1 | Config-field variant |
| FormatCEF_WithConfigFields | 439 | 224 | 1 | Config-field variant |

### Route Matching

| Benchmark | ns/op | allocs/op | Notes |
|-----------|------:|----------:|-------|
| MatchesRoute/empty_route | 1.7 | 0 | Trivial pass-through |
| MatchesRoute/include_categories | 3.2 | 0 | 4-entry include list |
| MatchesRoute/exclude_categories | 8.4 | 0 | 3-entry exclude list |
| MatchesRoute/include_event_types | 4.1 | 0 | 4-entry include list |
| MatchesRoute/include_20_categories | 6.7 | 0 | 20-entry include list |
| FilterCheck_Parallel | 1.0 | 0 | GOMAXPROCS goroutines, sync.Map lock-free reads |
| FilterCheck_ReadWriteContention | 1.0 | 0 | GOMAXPROCS readers + 1 writer toggling category |

### Output Backends

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| FileOutput_Write | ~67 | 160 | 1 | Enqueue hot path, diagnostic logger silenced |
| FileOutput_Write_Parallel | ~85 | 160 | 1 | RunParallel — channel contention |
| SyslogOutput_Write | 79 | 174 | 1 | TCP write enqueue, diagnostic logger silenced |
| loki.WriteWithMetadata | 64 | 77 | 1 | Single-event Loki enqueue |
| loki.BatchBuild | 72µs | 260Ki | 389 | 100 events grouped into push streams |
| loki.Gzip | 213µs | 1.0Mi | 380 | Gzip of realistic push payload |

### Key Observations

- **Audit** at **1 alloc/op** post-W2 (#497). The single remaining allocation is the defensive map clone on the slow path (`NewEvent` / `NewEventKV`). Generated builders on the fast path reach **0 allocs/op** at the drain side.
- **Audit_Parallel** at 1 alloc/op and ~64 ns amortised — lock-free filter + pooled entry, sub-linear scaling under contention.
- **AuditDisabledAuditor** at 18 ns — the `WithDisabled` early-return path. Effectively free.
- **JSONFormatter_Format** at 1 alloc/op — this benchmark exercises the public `Formatter.Format` path (which always copies before return for backward compatibility with third-party callers). The drain pipeline uses the internal `bufferedFormatter.formatBuf` path which leases the buffer and reaches 0 allocs/op end-to-end.
- **FilterCheck** at 0 allocs/op and ~16 ns — lock-free via `syncmap`.
- **MatchesRoute** at 0 allocs/op — O(n) scan, largest list (20 categories) at ~6.7 ns.
- **AppendPostFields_JSON** at 1 alloc/op exercises the pre-W2 public `AppendPostFields` path. The drain now uses in-place `appendPostFieldJSONInto` which mutates a per-event scratch buffer and contributes 0 allocs/op.
- **HMAC** direct `ComputeHMAC` at 8 allocs/op on the standalone benchmarks reflects the per-call `hmac.New` + hex-encoding cost. The `Audit_WithHMAC` full-path benchmark drops to **1 alloc/op** post-W2 (was 2) because the in-place HMAC append eliminates the scratch buffer allocation.
- **Fan-out** scales well: 3 outputs with shared formatter lands at ~370 ns; 5 outputs at ~344 ns — effectively constant because all outputs share one formatter-buffer lease and each output pays only for post-field assembly.
- **Output-backend enqueue** hot paths (`FileOutput_Write`, `SyslogOutput_Write`, `loki.WriteWithMetadata`) all land at 1 alloc/op — channel-send + one defensive data copy (the no-retention contract from #497 W2). Background goroutines handle batching, retries, and compression.

---

## History

| Date | Commit | Change | Audit allocs | JSON allocs |
|------|--------|--------|-------------:|------------:|
| 2026-03-28 | ad18b6f | Initial baseline (10 new benchmarks) | 14 | 26 |
| 2026-03-28 | c2711e7 | *EventDef pointers + pre-computed fields (#109, #107) | 13 | 25 |
| 2026-03-28 | 21e6828 | Lock-free filter (syncmap) + atomic route (#100, #110) | 14 | 25 |
| 2026-03-28 | 636db3e | Buffer pooling + writeJSONString + CEF single-pass (#101) | ~4 | **1** |
| 2026-03-28 | — | sync.Pool for auditEntry + fix flaky test (#112) | **3** | 1 |
| 2026-04-03 | a6e759c | JSON append: writeJSONString + pooled buffer (#229) | 4 | 1 |
| 2026-04-18 | 2a8625c | Track A refresh + pool/allocator settled (#493) | **2** | 1 |
| 2026-04-03 | 7aa14b7 | HMAC hash reuse + pre-allocated buffers (#230) | 4 (5 w/HMAC) | 1 |
