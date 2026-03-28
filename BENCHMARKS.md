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

**Date:** 2026-03-28
**Commit:** 636db3e (perf/formatter-pooling branch)
**Go:** 1.26.1
**CPU:** AMD Ryzen 9 7950X 16-Core (32 threads)
**OS:** Linux 6.14.0

### Core Audit Path

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit | 578 | 704 | 3 | 3 fields, enabled category, pooled entry |
| Audit_RealisticFields | 913 | 1232 | 5 | 10 fields, production-like |
| Audit_Parallel | 192 | 395 | 4 | 100 goroutines, per-op amortised |
| AuditDisabledCategory | 66 | 0 | 0 | Fast-path exit (syncmap) |
| Audit_EndToEnd | 613 | 698 | 3 | Large buffer, amortised caller cost |
| AuditDisabledLogger | 1.1 | 0 | 0 | Config.Enabled=false |

### Caller-Side Helpers

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| CopyFields | 150 | 336 | 2 | 6-field map copy |
| FilterCheck | 22 | 0 | 0 | isEnabled lock-free (syncmap) |

### Formatters

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| JSONFormatter_Format | 301 | 160 | 1 | 4 fields, buffer pooled, writeJSONString |
| JSONFormatter_Format_LargeEvent | 1103 | 641 | 1 | 20 fields |
| CEFFormatter_Format | 401 | 176 | 2 | 4 fields, buffer pooled, single-pass escape |
| CEFFormatter_Format_LargeEvent | 1330 | 600 | 4 | 20 fields |

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
- **Audit** at 4 allocs/op reflects the end-to-end cost including field copy, filter check, and drain-side formatting
- **FilterCheck** at 0 allocs/op is lock-free via syncmap; single-goroutine latency (~22 ns) is an intentional tradeoff for eliminating RWMutex cache-line contention under concurrent load
- **CEFFormatter** at 2 allocs/op: 1 for the copy-before-return, 1 from allFieldKeysSortedSlow in benchmarks with non-precomputed EventDefs
- **MatchesRoute** at 0 allocs/op is already optimal; O(n) scan is the concern for large lists
- **CopyFields** at 2 allocs/op is the minimum (map header + bucket array)

---

## History

| Date | Commit | Change | Audit allocs | JSON allocs |
|------|--------|--------|-------------:|------------:|
| 2026-03-28 | ad18b6f | Initial baseline (10 new benchmarks) | 14 | 26 |
| 2026-03-28 | c2711e7 | *EventDef pointers + pre-computed fields (#109, #107) | 13 | 25 |
| 2026-03-28 | 21e6828 | Lock-free filter (syncmap) + atomic route (#100, #110) | 14 | 25 |
| 2026-03-28 | 636db3e | Buffer pooling + writeJSONString + CEF single-pass (#101) | ~4 | **1** |
| 2026-03-28 | — | sync.Pool for auditEntry + fix flaky test (#112) | **3** | 1 |
