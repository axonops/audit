// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package iouring is a vectored-writer library for append-heavy
// log and WAL workloads. It uses Linux io_uring on capable
// kernels and falls back transparently to writev(2) on other
// Unix platforms. The selection is internal; callers do not need
// to probe the kernel or branch on platform.
//
// # Quick start
//
// The zero-ceremony form — use it when you want to write bytes
// and do not care about strategy selection or lifecycle:
//
//	f, err := os.OpenFile("audit.log",
//	    os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
//	if err != nil {
//	    return err
//	}
//	defer f.Close()
//
//	n, err := iouring.Writev(int(f.Fd()), [][]byte{a, b, c})
//
// No construction, no Close, no options. The package holds a
// lazily-initialised default [Writer] that serves every call.
// It is safe for concurrent use (internally serialised) at the
// cost of an uncontended mutex per call.
//
// # Explicit instance
//
// Construct your own [Writer] when you need a dedicated instance
// — typically to avoid sharing the default mutex under heavy
// concurrency, to force a specific [Strategy] in tests, or to
// attach a [slog.Logger] for startup diagnostics:
//
//	w, err := iouring.New()
//	if err != nil {
//	    return err
//	}
//	defer w.Close()
//	_, err = w.Writev(int(f.Fd()), bufs)
//
// A [Writer] returned by [New] is NOT safe for concurrent use;
// callers must serialise [Writer.Writev], [Writer.Write], and
// [Writer.Close]. The race detector catches violations.
//
// # Strategies
//
// A [Writer] picks one of two strategies at construction:
//
//   - [StrategyIouring] — Linux 5.5+ with IORING_FEAT_NODROP;
//     the fastest path for batched writes.
//   - [StrategyWritev]  — syscall writev(2) on Unix; portable
//     and allocation-free.
//
// On platforms without any vectored-write primitive (currently
// Windows), [New] returns an error wrapping [ErrUnsupported].
//
// The negotiated strategy is reported by [Writer.Strategy] and
// is stable for the writer's lifetime. Callers that want to
// test specifically for io_uring can call [IouringSupported] —
// but in the common case the package-level [Writev] handles
// everything.
//
// # File-descriptor contract
//
// The library never takes ownership of the file descriptor
// passed to [Writev] / [Writer.Writev] / [Writer.Write]. The
// caller is responsible for keeping the fd open for the duration
// of each call and closing it when finished; closing the fd
// during a call is undefined behaviour.
//
// # Concurrency
//
// The package-level [Writev] is safe for concurrent use via an
// internal mutex on the default writer. For higher throughput
// under heavy contention, construct one [Writer] per producer
// goroutine with [New] and serialise access to each writer.
//
// # Short writes
//
// All Writev entry points may return (n, nil) with n less than
// the sum of buffer lengths (for example when the destination
// is a pipe whose buffer is smaller than the iovec total).
// Callers are responsible for retrying the remainder. Byte
// counting follows writev(2): count is total bytes written
// across all iovecs, so advancing past a short write means
// skipping completed iovecs and slicing the first incomplete
// one. A minimal retry loop looks like:
//
//	written := 0
//	for written < total {
//	    n, err := iouring.Writev(fd, bufs)
//	    if err != nil {
//	        return err
//	    }
//	    written += n
//	    bufs = advance(bufs, n) // skip fully-written iovecs
//	}
//
// # Platform support
//
// v0.x supports Linux (io_uring or writev), Darwin (writev), and
// the *BSDs (writev). Windows callers receive [ErrUnsupported]
// from [New] and from the package-level [Writev]. Applications
// needing Windows coverage should fall back to a buffered
// [os.File.Write] loop at their layer.
//
// # Dependencies
//
// This package has no runtime dependencies beyond the Go standard
// library. It is safe to vendor into audit-sensitive deployments.
//
// # Stability
//
// v0.x exports writev-style submissions only. Future versions
// may add additional opcodes additively; the current surface is
// intentionally minimal.
//
// [writev(2)]: https://man7.org/linux/man-pages/man2/writev.2.html
package iouring
