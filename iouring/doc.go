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

// Package iouring is a vectored-writer library for append-heavy log
// and WAL workloads. It uses Linux io_uring on capable kernels and
// falls back transparently to syscall.writev on other Unix
// platforms. The selection is internal; callers do not need to
// probe the kernel or branch on platform.
//
// # Quick start
//
// The zero-ceremony form — use it when you just want to write
// bytes and do not care about strategy selection or lifecycle:
//
//	iouring.Writev(fd, [][]byte{a, b, c})
//
// No construction, no Close, no options. The package holds a
// lazily-initialised default [Writer] that serves every call. It
// is safe for concurrent use (internally serialised) at the cost
// of an uncontended mutex per call.
//
// # Explicit instance
//
// Construct your own [Writer] when you need a dedicated instance
// — typically to avoid sharing the default mutex under heavy
// concurrency, to force a specific [Strategy] in tests, or to
// hook a [slog.Logger] for startup diagnostics:
//
//	w, err := iouring.New()
//	if err != nil {
//	    return err
//	}
//	defer w.Close()
//	_, err = w.Writev(fd, bufs)
//
// A [Writer] returned by [New] is NOT safe for concurrent use —
// callers must serialise access to [Writer.Writev], [Writer.Write],
// and [Writer.Close]. The race detector catches violations.
//
// # Strategies
//
// A [Writer] picks one of three strategies at construction:
//
//   - [StrategyIouring] — Linux 5.5+ with IORING_FEAT_NODROP; the
//     fastest path for batched writes.
//   - [StrategyWritev]  — syscall writev(2) on Unix; portable and
//     allocation-free.
//   - [StrategyUnsupported] — no vectored I/O available (currently
//     Windows); [New] returns an error wrapping [ErrUnsupported].
//
// The negotiated strategy is reported by [Writer.Strategy] and is
// stable for the writer's lifetime. Callers that want to test for
// io_uring specifically can call [IouringSupported] — but in the
// common case the package-level [Writev] handles everything.
//
// # Concurrency
//
// The package-level [Writev] and [Write] are safe for concurrent
// use via an internal mutex on the default writer. For higher
// throughput under heavy contention, construct one [Writer] per
// producer goroutine with [New].
//
// # Short writes
//
// All [Writev] entry points may return (n, nil) with n less than
// the sum of buffer lengths. The caller is responsible for
// retrying the remainder. Byte counting follows [writev(2)]: count
// is total bytes written across all iovecs; callers advancing past
// a short write should skip completed iovecs and slice the first
// incomplete one.
//
// # Platform support
//
// v1.0 supports Linux (io_uring or writev), Darwin (writev), and
// the *BSDs (writev). Windows callers receive [ErrUnsupported]
// from [New]; the package-level [Writev] returns the same error.
// Applications needing Windows coverage should fall back to a
// buffered [os.File.Write] loop at their layer.
//
// # Project notes
//
// This package is developed in-repo as a submodule of
// github.com/axonops/audit; see audit issue #510. An extraction
// plan to a standalone github.com/axonops/iouring repository is
// tracked as audit issue #674.
//
// [writev(2)]: https://man7.org/linux/man-pages/man2/writev.2.html
package iouring
