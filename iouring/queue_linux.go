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

//go:build linux

package iouring

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// maxEAGAINRetries bounds EAGAIN retries from io_uring_enter.
// A kernel returning EAGAIN three consecutive times in the
// ~microsecond syscall loop is functionally wedged; surface the
// error rather than spin forever. EINTR is retried unbounded
// because signals (including Go's own preemption SIGURG) are
// routine on a busy runtime.
const maxEAGAINRetries = 3

// writev submits one IORING_OP_WRITEV and waits for its
// completion, returning bytes written (may be short) or an
// error. EINTR is retried transparently; EAGAIN is retried up
// to maxEAGAINRetries times.
//
// The SQE is tagged with a monotonic [ring.userDataCounter]
// and the CQ is scanned for the matching completion. The kernel
// is permitted to post CQEs in a different order than
// submissions (observed on Linux 6.x with IORING_FEAT_NATIVE_WORKERS),
// so the library must match on UserData rather than FIFO
// position.
//
// If io_uring_enter fails unrecoverably (not EINTR, exhausted
// EAGAIN retries, or any other error), the ring is poisoned —
// [ring.closed] is set and every subsequent call returns
// [ErrClosed]. The kernel may have queued the published SQE but
// we cannot reliably drain its future CQE, so continuing would
// risk returning a stale completion to a later caller. The
// caller should [Writer.Close] the ring and construct a new one.
//
// Contract: the caller guarantees no other goroutine
// concurrently accesses this ring. Violations are caught by
// `-race`.
func (r *ring) writev(fd int, bufs [][]byte) (n int, err error) {
	if r.closed.Load() != 0 {
		return 0, ErrClosed
	}
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(bufs) > MaxIovecs {
		return 0, fmt.Errorf("iouring: %d buffers exceeds max %d", len(bufs), MaxIovecs)
	}

	// Build the iovec scratch. Skip zero-length buffers — an
	// iovec with Base=&b[0] where len(b)==0 would panic the
	// index expression.
	iovs := r.iovScratch[:0]
	for i := range bufs {
		if len(bufs[i]) == 0 {
			continue
		}
		iovs = append(iovs, syscall.Iovec{
			Base: &bufs[i][0],
			Len:  uint64(len(bufs[i])),
		})
	}
	if len(iovs) == 0 {
		return 0, nil
	}

	// Defence-in-depth: the kernel's SQE.Fd is int32. A caller
	// passing an int that doesn't fit would get silently
	// truncated to a different fd and scribble on the wrong
	// file. Reject out-of-range values explicitly — only after
	// confirming we actually need to reach the kernel.
	if fd < 0 || fd > math.MaxInt32 {
		return 0, fmt.Errorf("iouring: fd %d out of int32 range", fd)
	}
	nrVecs := uint32(len(iovs))

	// Pin iovs and bufs across ALL kernel operations below — the
	// kernel may still be reading iovec memory when this function
	// returns on older kernels (pre-5.5 without
	// IORING_FEAT_SUBMIT_STABLE). Defer guarantees every return
	// path honours the invariant.
	defer runtime.KeepAlive(iovs)
	defer runtime.KeepAlive(bufs)

	// Acquire an SQE slot. Plain-atomic load of sqHead (kernel-
	// written) and sqTail (library-written, loaded for -race
	// cleanliness).
	head := atomic.LoadUint32(r.sqHead)
	tail := atomic.LoadUint32(r.sqTail)
	if tail-head >= r.sqEntries {
		// Ring is structurally full — can only happen if a prior
		// enter error has left orphaned SQEs; poison.
		r.closed.Store(1)
		return 0, ErrClosed
	}
	idx := tail & r.sqMask
	sqe := &r.sqesView[idx]

	// Tag this SQE with a unique UserData value. Zero is valid
	// but reserved for "fresh CQE that never carried a tag", so
	// the counter starts at 1 (pre-incremented).
	r.userDataCounter++
	tag := r.userDataCounter

	// Fill the SQE with plain stores. These happen-before the
	// atomic.StoreUint32 on sqTail below, so the kernel observes
	// a fully-populated SQE when it sees the new tail value.
	*sqe = ioUringSqe{}
	sqe.OpCode = ioringOpWritev
	sqe.Fd = int32(fd)
	sqe.Off = ^uint64(0) // "current file position" sentinel; safe for O_APPEND
	sqe.Addr = uint64(uintptr(unsafe.Pointer(&iovs[0])))
	sqe.Len = nrVecs
	sqe.UserData = tag

	// Release-store the new tail — publishes the SQE.
	atomic.StoreUint32(r.sqTail, tail+1)

	// Submit and wait. On unrecoverable error, poison the ring —
	// the orphaned SQE cannot be safely reconciled later.
	eagainRetries := 0
	for {
		_, enterErr := ioUringEnter(r.fd, 1, 1, ioringEnterGetEvents)
		if enterErr == nil {
			break
		}
		if errors.Is(enterErr, syscall.EINTR) {
			continue
		}
		if errors.Is(enterErr, syscall.EAGAIN) && eagainRetries < maxEAGAINRetries {
			eagainRetries++
			continue
		}
		r.closed.Store(1)
		return 0, fmt.Errorf("iouring: io_uring_enter: %w", enterErr)
	}

	// Scan the CQ for the completion matching our UserData tag.
	// Other CQEs we encounter are completions from earlier
	// kernel reordering — skip them, releasing their ring slots.
	// If the CQ drains without a match, block via
	// io_uring_enter(submit=0, wait=1).
	for {
		cqTail := atomic.LoadUint32(r.cqTail)
		cqHead := atomic.LoadUint32(r.cqHead)
		for cqHead != cqTail {
			cqe := &r.cqesView[cqHead&r.cqMask]
			if cqe.UserData == tag {
				res := cqe.Res
				atomic.StoreUint32(r.cqHead, cqHead+1)
				if res < 0 {
					return 0, syscall.Errno(-res)
				}
				return int(res), nil
			}
			// Not ours — a completion from an earlier write that
			// the kernel reordered. The earlier caller has already
			// returned (we're single-goroutine). Release the slot
			// and keep scanning.
			atomic.StoreUint32(r.cqHead, cqHead+1)
			cqHead++
		}
		// CQ drained without finding our tag — wait for more.
		if _, enterErr := ioUringEnter(r.fd, 0, 1, ioringEnterGetEvents); enterErr != nil {
			if errors.Is(enterErr, syscall.EINTR) {
				continue
			}
			r.closed.Store(1)
			return 0, fmt.Errorf("iouring: io_uring_enter wait: %w", enterErr)
		}
	}
}
