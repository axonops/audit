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
**Commit:** ad18b6f (perf/missing-benchmarks branch)
**Go:** 1.26.1
**CPU:** AMD Ryzen 9 7950X 16-Core (32 threads)
**OS:** Linux 6.14.0

### Core Audit Path

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| Audit | 840 | 871 | 14 | 3 fields, enabled category |
| Audit_RealisticFields | 1487 | 2065 | 24 | 10 fields, production-like |
| Audit_Parallel | 218 | 401 | 5 | 100 goroutines, per-op amortised |
| AuditDisabledCategory | 86 | 0 | 0 | Fast-path exit |
| Audit_EndToEnd | 875 | 881 | 14 | Large buffer, amortised caller cost |
| AuditDisabledLogger | 1.4 | 0 | 0 | Config.Enabled=false |

### Caller-Side Helpers

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| CopyFields | 164 | 336 | 2 | 6-field map copy |
| FilterCheck | 22 | 0 | 0 | isEnabled lock-free (syncmap) |

### Formatters

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| JSONFormatter_Format | 1209 | 985 | 26 | 4 fields |
| JSONFormatter_Format_LargeEvent | 5145 | 4775 | 79 | 20 fields |
| CEFFormatter_Format | 733 | 400 | 3 | 4 fields |
| CEFFormatter_Format_LargeEvent | 3290 | 3456 | 10 | 20 fields |

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

- **JSONFormatter** at 26 allocs/op (4 fields) and 79 allocs/op (20 fields) is the primary optimisation target
- **Audit_RealisticFields** at 24 allocs/op shows the real per-request cost with production field counts
- **FilterCheck** single-goroutine at 13 ns is slightly slower than the pre-syncmap RWMutex baseline (~10 ns) due to sync.Map indirection. This is an intentional tradeoff: sync.Map eliminates RWMutex reader-counter cache-line contention under hundreds of concurrent goroutines. The parallel benchmarks (FilterCheck_Parallel, FilterCheck_ReadWriteContention) demonstrate stable throughput under heavy concurrent load.
- **MatchesRoute** at 0 allocs/op is already optimal; O(n) scan is the concern for large lists
- **CopyFields** at 2 allocs/op is the minimum (map header + bucket array)

---

## History

| Date | Commit | Change | Audit allocs | JSON allocs |
|------|--------|--------|-------------:|------------:|
| 2026-03-28 | ad18b6f | Initial baseline (10 new benchmarks) | 14 | 26 |
| 2026-03-28 | c2711e7 | *EventDef pointers + pre-computed fields (#109, #107) | 13 | 25 |
| 2026-03-28 | 21e6828 | Lock-free filter (syncmap) + atomic route (#100, #110) | 14 | 25 |
| 2026-03-28 | 636db3e | Buffer pooling + writeJSONString + CEF single-pass (#101) | ~8 | **1** |
