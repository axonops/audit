# ADR 0002: File Output io_uring Fast Path

- **Status:** Accepted (2026-04-20)
- **Issue:** [#510](https://github.com/axonops/audit/issues/510)
- **Reviewers:** test-analyst (APPROVED), api-ergonomics-reviewer (APPROVED after 3 iterations), security-reviewer (APPROVED), code-reviewer (APPROVED)
- **Supersedes:** —
- **Extraction tracker:** [#674](https://github.com/axonops/audit/issues/674)

## Context

The file output's per-event `write(2)` syscall dominates steady-state
CPU at the target ingest rate for audit-heavy workloads. On `audit/file/`,
every `Write` call goes through `bufio.Writer` + explicit `Flush` (per
the [#450 prompt-visibility contract][450]), producing one syscall per
event. At 10 k events/s that is 10 k syscalls/s of pure overhead —
the actual byte count is small (audit events average 200–500 bytes) so
I/O bandwidth is never the bottleneck; only syscall cost is.

Two primitives can amortise that cost:

1. **`writev(2)`** — vectored write, submitting an iovec array in one
   syscall. Universally available on Unix. Reduces N syscalls to 1.
2. **io_uring** — Linux 5.1+ asynchronous I/O interface. A submission
   queue (SQ) and completion queue (CQ) shared via mmap with the
   kernel, plus an `io_uring_enter` syscall. Potentially reduces to
   zero syscalls per batch under SQPOLL, or one per batch in the
   simple blocking submit-and-wait pattern.

[450]: https://github.com/axonops/audit/pull/450

The file output's `writeLoop` goroutine already serialises all writes
to a single fd per output; the consumer pattern is "single-owner
batch-and-write", which is exactly what io_uring's minimal-synchronous
variant was designed for.

## Options Considered

### (a) Depend on an existing Go io_uring library

Three candidate upstream libraries exist:

| Library | Age | Shape | Notes |
|---|---|---|---|
| `github.com/iceber/iouring-go` | ~2 y stale | High-level, background goroutine + eventfd + callback-per-SQE | Over-engineered for a single-owner submit-and-wait caller; no releases in years |
| `github.com/ii64/gouring` | ~18 mo stale | Low-level, fd-bound, synchronous | Closest match but fragile `go:linkname syscall.mmap` trick |
| `github.com/pawelgaczynski/giouring` | ~18 mo stale | Direct liburing port; comprehensive opcode coverage | Much larger surface than we need; depends on `golang.org/x/sys/unix` |

All three are ≥ 18 months stale; none has active release cadence.
Pulling a dead upstream onto the audit hot path is a supply-chain
liability: a kernel ABI change (the io_uring struct layouts have
grown across 5.4 → 6.10) without a maintainer means we silently
ship a broken library.

**Rejected.**

### (b) `syscall.Writev` only

Universal, zero-dependency, works on every Unix. Collapses N
syscalls to 1 per batch and is essentially free to adopt.

Leaves io_uring's asynchronous potential on the table, but for our
current single-owner submit-and-wait pattern that potential is
small. Benchmarks support this — see below.

**Considered but extended** to a two-tier fallback in option (c).

### (c) Own, in-repo wrapper with internal fallback (chosen)

Build a minimal Linux io_uring wrapper as an in-repo submodule,
plus a `syscall.Writev` fallback, plus a package-level default
Writer that handles strategy selection internally. Consumer calls
`iouring.Writev(fd, bufs)` and gets the fastest available path on
the current kernel — io_uring on Linux 5.5+, `writev(2)` on older
Linux and non-Linux Unix, `ErrUnsupported` on Windows.

**Accepted.**

### (d) CGo binding to liburing

Rejected for cross-compilation headaches (every consumer now
needs a C toolchain) and marginal gains over option (c) (the
unsafe-pointer cost of our hand-rolled wrapper is nearly zero).

## Decision

Ship `audit/iouring/` as a new submodule at module path
`github.com/axonops/audit/iouring`. Two-tier public API:

- **Tier 1** — `iouring.Writev(fd, bufs)` package-level function.
  Zero ceremony, safe for concurrent use via an internal mutex
  on a lazily-initialised default Writer.
- **Tier 2** — `iouring.New(opts...)` returns a dedicated `*Writer`.
  Not safe for concurrent use; for producers that want to avoid
  the default-writer mutex.

Strategy selection is **internal** to the library:

1. **StrategyIouring** — Linux 5.5+ with IORING_FEAT_NODROP.
2. **StrategyWritev** — every other Unix platform, or Linux where
   io_uring_setup failed for any reason (RLIMIT_MEMLOCK, seccomp,
   etc.).
3. Windows — `ErrUnsupported`.

The submodule is structured as a standalone library so the
eventual extraction to `github.com/axonops/iouring` (issue #674)
is a copy-and-bump-require move, not a rewrite.

The file output's `writeLoop` consumes the Tier-1 API:

- Blocks for the first pending event.
- Non-blockingly drains up to `maxBatch=256` additional events.
- Submits one `iouring.Writev` call per batch.
- No artificial latency — a single pending event submits a
  one-iovec batch immediately.

## Consequences

### Positive

- Syscall count at steady-state: 1 per batch instead of N per
  batch. At 10 k events/s with average batch size ~64 that is
  ~156 syscalls/s instead of 10 k.
- Zero allocations on the hot path. Verified via
  `BenchmarkWriter_Writev` (see [BENCHMARKS.md](../../BENCHMARKS.md#iouring-submodule)):
  all strategies report `0 B/op 0 allocs/op` across every batch
  size.
- Public API of `file.Output` unchanged — the integration is
  below the consumer-visible surface. Existing `@file` BDD
  scenarios pass unchanged.
- The io_uring primitive is reusable for the post-v1.0 WAL
  design (decision #5 in the parent tracker).
- Extraction-ready: the submodule has zero external dependencies
  beyond `syscall` and `sync/atomic`.

### Negative

- **On tmpfs and small-batch workloads, `syscall.Writev` is
  measurably faster than io_uring.** See BENCHMARKS.md — at
  batch 1 on tmpfs, io_uring is ~11× slower than writev
  (6977 vs 602 ns/op) because the SQE/CQE ring management
  dominates the lightweight page-cache copy. io_uring closes
  the gap as batch size grows but still trails writev at
  batch 1024 on tmpfs (95918 vs 87987 ns/op). **io_uring's
  advantage materialises on real-disk workloads with overlapping
  I/O and a slow-device baseline** — a regime our AC #5 did not
  gate on.
- `unsafe.Pointer` + syscall surface increases the security
  review load. Mitigated by: confining unsafe code to the two
  syscall boundaries it actually needs (the Linux io_uring
  `*_linux.go` files and a single `&iovs[0]` cast in
  `strategy_writev_unix.go` for the SYS_WRITEV call, required
  on every Unix), plus applying the full security-reviewer
  punch list (runtime.KeepAlive via defer, fd range validation,
  ring-poisoning on unrecoverable errors, IORING_FEAT_NODROP
  requirement, atomic CAS close gate, SINGLE_MMAP-aware munmap).
- Cross-platform matrix is more complex: `//go:build linux`,
  `//go:build unix && !linux`, `//go:build !unix` guard
  strategy implementations.
- The hand-rolled wrapper is maintenance the project did not
  previously carry. Extraction to `github.com/axonops/iouring`
  (#674) accepts this debt as a first-class project.

### Neutral

- The `maxBatch=256` constant in `file.Output.writeLoop` is
  chosen for a 4-KiB pre-allocated iovec scratch (each
  `syscall.Iovec` is 16 bytes) with modest room to grow. Tuning
  this is a pure performance knob with no correctness impact.
- No new consumer-visible config knobs. Operators who want to
  force one strategy can use `iouring.WithStrategy` via code,
  not environment — on purpose, because process-global env
  knobs that flip hot-path behaviour are a debugging nightmare
  on large fleets.

## CQE Reordering Gotcha (recorded)

During file-module stress testing we observed Linux 6.x with
`IORING_FEAT_NATIVE_WORKERS` posting CQEs in a different order
than submissions, even for a single submitter. A naive
"consume-CQE-at-head" implementation returned the wrong
byte count for 1-in-10 to 1-in-30 writes, and the file
module's short-write retry loop doubled the tail of earlier
batches on disk as a result.

The fix: every SQE is tagged with a monotonic `uint64` UserData
counter; `ring.writev` scans forward in the CQ for the
matching tag and discards any earlier (already-returned)
completions as it goes. This matches `liburing`'s multishot
pattern but for single-shot submissions. The behaviour is
covered by `TestRing_StressRoundTrip` and the corresponding
white-box `TestRing_UserDataMonotonic`.

## Extraction Plan

Tracked as [#674](https://github.com/axonops/audit/issues/674).
The in-repo submodule is a verbatim copy of what the standalone
repo will ship:

1. Create `github.com/axonops/iouring` on the AxonOps org.
2. `git subtree split` (or `git filter-repo`) on `audit/iouring/`.
3. Tag `v0.1.0`. No API changes — the shape was reviewed for
   extraction before merge.
4. In `axonops/audit`: replace the in-repo submodule with a
   `require github.com/axonops/iouring vX.Y.Z`.

Timing: after v1.0.0 of `axonops/audit` ships and the submodule
has at least one minor version of production use.

## References

- [liburing](https://github.com/axboe/liburing) — C reference
- [Linux io_uring](https://man7.org/linux/man-pages/man7/io_uring.7.html) — kernel interface
- [writev(2)](https://man7.org/linux/man-pages/man2/writev.2.html) — POSIX fallback
- `project_iouring_research.md` — pinned research memo covering
  the correctness patterns harvested from the three surveyed
  Go libraries.
