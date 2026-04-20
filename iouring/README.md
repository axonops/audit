# iouring

[![Go Reference][godoc-badge]][godoc] [![Go Report Card][goreport-badge]][goreport]

A minimal, zero-dependency Go vectored-writer library for
append-heavy log and WAL workloads. Uses Linux `io_uring` on
capable kernels and falls back transparently to `writev(2)` on
other Unix platforms.

## Why

The common pattern for log writers is one `write(2)` syscall per
event. At 10 000 events/s that's 10 000 syscalls/s of pure
overhead — audit events rarely exceed 500 bytes so device I/O is
not the bottleneck; syscall cost is. This library collapses N
events into one vectored submission, amortising the syscall
overhead across the whole batch, and picks the fastest available
primitive on the current kernel.

## Install

```bash
go get github.com/axonops/audit/iouring
```

Requires Go 1.22+. No runtime dependencies beyond the Go standard
library.

## Quick start

Zero ceremony. Use it when you just want to write bytes and do
not care about strategy selection or lifecycle:

```go
import "github.com/axonops/audit/iouring"

f, _ := os.OpenFile("audit.log",
    os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
defer f.Close()

// Writev takes int, not uintptr — cast the os.File fd.
n, err := iouring.Writev(int(f.Fd()), [][]byte{
    []byte("hello "),
    []byte("io_uring\n"),
})
```

Safe for concurrent use — an internal mutex on a lazily-
initialised default `Writer` serialises calls.

## Explicit instance

Construct your own `Writer` when you want a dedicated instance —
typically to avoid sharing the default mutex under heavy
concurrency, to force a specific strategy in tests, or to hook
a `*slog.Logger` for startup diagnostics:

```go
w, err := iouring.New()
if err != nil {
    return err
}
defer w.Close()
_, err = w.Writev(int(f.Fd()), bufs)
```

A `Writer` returned by `New` is NOT safe for concurrent Writev
calls — callers must serialise.

## Strategies

A `Writer` picks one of two strategies at construction:

| Strategy              | Requirement                             | Used for                         |
|-----------------------|-----------------------------------------|----------------------------------|
| `StrategyIouring`     | Linux 5.5+ with `IORING_FEAT_NODROP`    | The fastest path on capable hosts |
| `StrategyWritev`      | Any Unix (Linux, Darwin, *BSD)          | Portable fallback                |

On Windows, `New` returns an error wrapping `ErrUnsupported` —
the library exposes no vectored-write primitive there.

The negotiated strategy is reported by `(w *Writer).Strategy()`
and is stable for the Writer's lifetime:

```go
if w.Strategy() == iouring.StrategyIouring {
    // running on io_uring
}
```

## Short writes

`Writev` may return `(n, nil)` with `n` less than the sum of
buffer lengths — for example when writing to a pipe whose buffer
is smaller than the iovec total. Callers are responsible for
retrying the remainder:

```go
written := 0
for written < total {
    n, err := w.Writev(fd, bufs)
    if err != nil { return err }
    written += n
    bufs = advance(bufs, n) // skip fully-written iovecs
}
```

## fd ownership

The library never takes ownership of the file descriptor passed
to `Writev` / `Write`. The caller retains fd lifecycle
responsibility: keep the fd open for the duration of each call
and close it when finished. Closing the fd during a call is
undefined behaviour.

## Concurrency

- **Package-level `iouring.Writev`** is safe for concurrent use
  via an internal mutex on the default writer.
- **`(*Writer).Writev` / `.Write`** are NOT safe for concurrent
  calls; serialise them in the caller.
- **`(*Writer).Close`** is idempotent and safe to call from any
  goroutine relative to itself — but not concurrently with a
  Writev. Serialise the close against any in-flight writes.

For higher parallel throughput than the default mutex allows,
construct one `Writer` per producer with `New()`.

## Benchmarks

On an AMD Ryzen 9 7950X, Linux kernel 6.14, `/dev/shm` target,
256-byte events, zero allocations across every path:

| Strategy | Batch | ns/op | MB/s |
|----------|------:|------:|-----:|
| iouring  | 1     | 6 404 |   40 |
| iouring  | 1024  | 100 242 | 2 615 |
| writev   | 1     |   591 |  433 |
| writev   | 1024  | 89 274 | 2 936 |

On tmpfs, `syscall.writev(2)` actually beats `io_uring` at every
batch size because the SQE/CQE ring management costs more than a
single `writev(2)` does for page-cache writes. **io_uring earns
its place on real disks** where submissions can overlap with
in-flight I/O — a regime tmpfs cannot simulate. Run the
benchmarks on your production storage target to see the real
delta.

Full matrix in [BENCHMARKS.md in the parent repo][bench].

## Correctness notes

- **CQE reordering.** On Linux 6.x kernels with
  `IORING_FEAT_NATIVE_WORKERS`, the kernel is permitted to post
  CQEs in a different order than submissions. The library tags
  every SQE with a monotonic `UserData` counter and scans the CQ
  for the matching tag, discarding any earlier completions it
  encounters. This makes the library robust against kernel
  reordering while preserving the single-goroutine contract.
- **IORING_FEAT_NODROP required.** A full CQ on a kernel without
  NODROP silently drops completions — an unacceptable failure
  mode for audit-grade writers. `New` fails fast on kernels that
  don't advertise NODROP (pre-5.5).
- **Ring poisoning on unrecoverable errors.** A failed
  `io_uring_enter` leaves the SQE published to the kernel with
  no safe way to drain its future completion; the library sets
  a permanent closed flag and returns `ErrClosed` from subsequent
  calls. Recovery requires Close + New.

## Platform support

| Platform           | Strategy         | Notes                           |
|--------------------|------------------|---------------------------------|
| linux/amd64        | iouring / writev | 5.5+ with NODROP for iouring    |
| linux/arm64        | iouring / writev | Same as amd64                   |
| darwin/arm64       | writev           | BSD `writev(2)`                 |
| darwin/amd64       | writev           | BSD `writev(2)`                 |
| freebsd, openbsd   | writev           | Portable writev(2)              |
| windows            | unsupported      | `New` returns `ErrUnsupported`  |

## Stability

v0.x. The public API is small (12 exported symbols) and
intentionally minimal. Future versions may add additional
opcodes (fsync, read) additively; the current surface is stable.

## License

Apache 2.0. See [LICENSE][license].

## Status and extraction

This library is developed in-repo as a submodule of
[`github.com/axonops/audit`][parent]; the source of truth today
lives at `audit/iouring/`. Extraction to a standalone
`github.com/axonops/iouring` repository is tracked as
[audit issue #674][extract]; at that point the package import
path and API will remain unchanged, and this submodule will be
removed from the parent repo in favour of a `require` line.

[godoc]: https://pkg.go.dev/github.com/axonops/audit/iouring
[godoc-badge]: https://pkg.go.dev/badge/github.com/axonops/audit/iouring.svg
[goreport]: https://goreportcard.com/report/github.com/axonops/audit
[goreport-badge]: https://goreportcard.com/badge/github.com/axonops/audit
[bench]: https://github.com/axonops/audit/blob/main/BENCHMARKS.md#iouring-submodule
[license]: https://github.com/axonops/audit/blob/main/LICENSE
[parent]: https://github.com/axonops/audit
[extract]: https://github.com/axonops/audit/issues/674
