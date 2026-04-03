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

**Date:** 2026-04-03
**Commit:** 7aa14b7 (perf/hmac-hash-reuse branch)
**Go:** 1.26.1
**CPU:** AMD Ryzen 9 7950X 16-Core (32 threads)
**OS:** Linux 6.14.0

### Core Audit Path

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit | 617 | 758 | 4 | 3 fields, enabled category, pooled entry |
| Audit_RealisticFields | 1068 | 1306 | 7 | 10 fields, production-like |
| Audit_Parallel | 229 | 390 | 5 | GOMAXPROCS goroutines, per-op amortised |
| AuditDisabledCategory | 526 | 696 | 4 | Category disabled; drain skips write |
| Audit_EndToEnd | 658 | 738 | 4 | Large buffer, amortised caller cost |
| AuditDisabledLogger | 17 | 24 | 1 | Config.Enabled=false |

### Fan-Out (multi-output)

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| FanOut_SharedFormatter | 719 | 1053 | 5 | 3 outputs, same formatter (serialise once) |
| FanOut_MixedFormatters | 809 | 933 | 6 | 3 outputs, 2 formatters (JSON + CEF) |
| FanOut_FilteredOutputs | 683 | 877 | 5 | 3 outputs, 1 filtered by route |
| FanOut_5Outputs | 740 | 1293 | 6 | 5 outputs, same formatter |

### HMAC Pipeline

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit_WithHMAC | 796 | 879 | 5 | SHA-256, pre-constructed hash.Hash + buffer reuse |

### Post-Serialisation Append

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| AppendPostFields_JSON | 79 | 160 | 1 | writeJSONString + pooled buffer (was 6 allocs) |
| AppendPostFields_CEF | 60 | 192 | 2 | cefEscapeExtValue direct write |
| AppendPostFields_Disabled | 1.3 | 0 | 0 | nil fields fast path |

### Caller-Side Helpers

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| CopyFields | 150 | 336 | 2 | 6-field map copy |
| FilterCheck | 22 | 0 | 0 | isEnabled lock-free (syncmap) |

### Formatters

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| JSONFormatter_Format | 324 | 176 | 1 | 4 fields, buffer pooled, writeJSONString |
| JSONFormatter_Format_LargeEvent | 1104 | 640 | 1 | 20 fields |
| CEFFormatter_Format | 407 | 176 | 2 | 4 fields, buffer pooled, single-pass escape |
| CEFFormatter_Format_LargeEvent | 1273 | 600 | 4 | 20 fields |

### Route Matching

| Benchmark | ns/op | allocs/op | Notes |
|-----------|------:|----------:|-------|
| MatchesRoute/empty_route | 1.5 | 0 | Trivial pass-through |
| MatchesRoute/include_categories | 2.8 | 0 | 4-entry include list |
| MatchesRoute/exclude_categories | 6.7 | 0 | 3-entry exclude list |
| MatchesRoute/include_event_types | 3.4 | 0 | 4-entry include list |
| FilterCheck_Parallel | 31 | 0 | 3200 goroutines, sync.Map lock-free reads |
| FilterCheck_ReadWriteContention | 36 | 0 | 3200 readers + 1 writer toggling category |

### Key Observations

- **JSONFormatter** at 1 alloc/op after buffer pooling and writeJSONString; the remaining allocation is the copy-before-return required for formatCached safety
- **Audit** at 4 allocs/op reflects the caller-side cost (field copy + event interface) plus drain-side formatting
- **FilterCheck** at 0 allocs/op is lock-free via syncmap; single-goroutine latency (~22 ns) is an intentional tradeoff for eliminating RWMutex cache-line contention under concurrent load
- **CEFFormatter** at 2 allocs/op: 1 for the copy-before-return, 1 from allFieldKeysSortedSlow in benchmarks with non-precomputed EventDefs
- **MatchesRoute** at 0 allocs/op is already optimal; O(n) scan is the concern for large lists
- **CopyFields** at 2 allocs/op is the minimum (map header + bucket array)
- **AppendPostFields_JSON** at 1 alloc/op after replacing `json.Marshal` with `writeJSONString` + pooled buffer (#229). Down from 6 allocs
- **HMAC pipeline** at 5 allocs/op (1 extra vs base path) after hash reuse via `Reset()` + pre-allocated sum/hex buffers (#230). Down from 8 extra allocs via `ComputeHMAC`
- **Fan-out** scales well: 3 outputs with shared formatter adds ~102 ns (+16%) over 1 output. The formatCache serialises once and delivers the same `[]byte` to all outputs sharing a formatter. Route-filtered outputs add minimal overhead (~66 ns). Even 5 outputs adds only ~123 ns (+20%)

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
| 2026-04-03 | 7aa14b7 | HMAC hash reuse + pre-allocated buffers (#230) | 4 (5 w/HMAC) | 1 |
