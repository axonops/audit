# Soak Benchmark (`make soak`)

The soak driver (`BenchmarkSoak_MixedOutputs` in `soak_test.go`) is
the pre-release verification harness mandated by issue #573 / Track
F-52. It exercises the audit hot path with mixed outputs for
`SOAK_DURATION` (default 12 hours) so memory leaks, goroutine leaks,
and bounded-resource invariants surface BEFORE a release tag.

## What it does

- Wires file + in-process syslog (TCP) + httptest webhook outputs
  in one auditor.
- Drives `SOAK_PRODUCERS` (default 8) producer goroutines at
  `SOAK_RATE` events/sec aggregate (default 5000) across three
  weighted event templates: 60% routine, 30% medium, 10% large
  multi-field.
- Samples `runtime.MemStats.HeapAlloc`, `runtime.NumGoroutine()`,
  GC counters, audit queue depth, and total events / drops every
  `SOAK_SAMPLE_INTERVAL` (default 1 minute).
- Writes one CSV row per sample to
  `$SOAK_OUTPUT_DIR/soak-samples-<timestamp>.csv` and a JSON
  summary to `soak-summary-<timestamp>.json`.
- Asserts at end-of-run: heap and goroutine counts MUST stay within
  2× the start values. Real bound review is the maintainer's job
  on the full CSV.
- Runs under `goleak.VerifyTestMain`, so leaked goroutines fail the
  benchmark process.

## How to run

```bash
# Full 12-hour run before tagging a release
make soak

# 1-minute smoke test (verify harness compiles + runs)
make soak-quick

# Custom duration / rate
make soak SOAK_DURATION=2h SOAK_RATE=10000

# Custom output directory
make soak SOAK_OUTPUT_DIR=/var/tmp/audit-soak
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SOAK_DURATION` | `12h` | Wall-clock run length (any `time.ParseDuration` value) |
| `SOAK_PRODUCERS` | `8` | Concurrent producer goroutines |
| `SOAK_RATE` | `5000` | Aggregate events/sec target |
| `SOAK_SAMPLE_INTERVAL` | `1m` | How often to capture a runtime snapshot |
| `SOAK_OUTPUT_DIR` | `./soak-output` | Where samples + summary land |

## Interpreting results

The CSV columns are:

```
elapsed_seconds, heap_alloc_mb, heap_sys_mb, num_goroutine,
num_gc, pause_total_ms, audit_queue_len, audit_queue_cap,
total_events, total_drops
```

A clean 12-hour run looks like:

- **`heap_alloc_mb`**: oscillates between GC cycles but the median
  remains roughly constant. A monotonically-increasing line is a
  leak — investigate before tagging.
- **`num_goroutine`**: stable after the first minute (output drain
  goroutines warm up, then steady-state). Drift upward over hours
  is a leak.
- **`audit_queue_len`**: should stay near zero on a healthy run —
  any sustained non-zero value means an output cannot keep up at
  `SOAK_RATE`.
- **`total_drops`**: should be 0. Drops indicate the auditor's
  internal queue overflowed (`SOAK_RATE` too high for the
  hardware) — drop the rate or investigate.

## Pre-release workflow

1. On stable hardware (consistent CPU, no other load), run
   `make soak`.
2. After 12 hours, read `$SOAK_OUTPUT_DIR/soak-summary-*.json`.
3. Paste the start / end / peak values into `BENCHMARKS.md`
   "Release Soak-Test Summary" under a new dated entry for the
   pending release.
4. If heap or goroutine count is unbounded, OR `goleak` reported
   failures, OR drops are non-zero — investigate before tagging.

`make soak-quick` (1 minute) verifies the harness compiles and
runs to completion before the maintainer commits to a 12-hour run
on the release-prep machine.

## Why not in CI?

A 12-hour run consumes 12 hours of GitHub Actions billable time
per release; not every PR needs one. The soak is operator-owned
and runs once per release cycle on stable hardware. CI runs
`goreleaser check` and the unit / BDD suites — those catch
shorter-cycle leaks. The 12-hour run catches the slow leaks that
short cycles cannot.

If you have a self-hosted runner with the time budget, you can
add a workflow that calls `make soak` on a `release/*` branch.
The harness is unchanged.
