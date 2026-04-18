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

**Date:** 2026-04-18
**Commit:** 2a8625c (post-Track-A; branch feature/493-benchmark-baseline-ci)
**Go:** 1.26+
**CPU:** AMD Ryzen 9 7950X 16-Core (32 threads)
**OS:** Linux 6.14.0
**Samples:** `count=5` per benchmark; benchstat confidence requires ≥6 so the current report is indicative (`± ∞`). Compare rather than read absolutes.

### Core Audit Path

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit | 376 | 324 | 2 | 3 fields, enabled category, pooled entry |
| Audit_RealisticFields | 816 | 678 | 2 | 10 fields, production-like |
| Audit_Parallel | 61 | 26 | 1 | GOMAXPROCS goroutines, per-op amortised |
| AuditDisabledCategory | 284 | 239 | 1 | Category disabled; drain skips write |
| Audit_EndToEnd | 404 | 329 | 2 | Large buffer, amortised caller cost |
| AuditDisabledAuditor | 18 | 24 | 1 | WithDisabled auditor — early return |

### Fan-Out (multi-output)

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| FanOut_SharedFormatter | 348 | 463 | 2 | 3 outputs, same formatter (serialise once) |
| FanOut_MixedFormatters | 351 | 347 | 2 | 3 outputs, 2 formatters (JSON + CEF) |
| FanOut_FilteredOutputs | 364 | 409 | 2 | 3 outputs, 1 filtered by route |
| FanOut_5Outputs | 338 | 511 | 2 | 5 outputs, same formatter |

### HMAC Pipeline

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit_WithHMAC | 369 | 342 | 2 | Full Audit path with HMAC-SHA-256 appended |
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

### Formatters

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| JSONFormatter_Format | 349 | 176 | 1 | 4 fields, buffer pooled, writeJSONString |
| JSONFormatter_Format_LargeEvent | 1208 | 640 | 1 | 20 fields |
| CEFFormatter_Format | 382 | 160 | 1 | 4 fields, buffer pooled, single-pass escape |
| CEFFormatter_Format_LargeEvent | 1196 | 584 | 4 | 20 fields |
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

- **Audit** at 2 allocs/op — steady state for the caller-side hot path (field copy + entry acquire). Down from 4 allocs under the earlier baseline after the #473/#474 fixes and the `sync.Pool`-backed entry design.
- **Audit_Parallel** at 1 alloc/op and ~61 ns amortised — the lock-free filter + pooled entry path scales linearly; per-op cost drops because GOMAXPROCS goroutines amortise the fixed construction work.
- **AuditDisabledAuditor** at 18 ns — the `WithDisabled` early-return path. Effectively free when consumers wire auditing off conditionally.
- **JSONFormatter** at 1 alloc/op — the remaining allocation is the copy-before-return required for `formatCached` safety. `CEFFormatter_Format` also lands at 1 alloc/op on the non-large variant.
- **FilterCheck** at 0 allocs/op and ~16 ns — lock-free via `syncmap`. The parallel and read/write-contention variants measure ~1 ns amortised because the lock-free design avoids RWMutex cache-line contention entirely.
- **MatchesRoute** at 0 allocs/op — O(n) scan, largest measured list (20 categories) still lands at ~6.7 ns.
- **AppendPostFields_JSON** at 1 alloc/op after replacing `json.Marshal` with `writeJSONString` + pooled buffer.
- **HMAC** direct `ComputeHMAC` at 8 allocs/op on the standalone benchmarks reflects the per-call `hmac.New` + hex-encoding cost. The `Audit_WithHMAC` full-path benchmark stays at 2 allocs/op because the hot-path reuses pre-allocated hash state (#473/hmac.go:newHMACState).
- **Fan-out** scales well: 3 outputs with shared formatter lands at ~348 ns vs ~376 ns for 1 output (+7%). 5 outputs lands at ~338 ns (actually slightly faster on this run due to run-to-run variance; at count=5 the 95% CI is `± ∞` so treat small deltas as noise).
- **Output-backend enqueue** hot paths (`FileOutput_Write`, `SyslogOutput_Write`, `loki.WriteWithMetadata`) all land at 1 alloc/op — the drain-loop write path is effectively channel-send + data-copy. Background goroutines handle batching, retries, and compression.

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
