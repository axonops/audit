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
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// maxEAGAINRetries bounds EAGAIN retries from io_uring_enter. A
// wedged kernel returning EAGAIN forever would otherwise pin the
// calling goroutine.
const maxEAGAINRetries = 3

// writev submits one IORING_OP_WRITEV and waits for its completion.
// Returns bytes written (may be short) or an error. EINTR is
// retried transparently; EAGAIN is retried up to maxEAGAINRetries.
//
// Contract: the caller guarantees no other goroutine concurrently
// accesses this ring. Violations are caught by `-race`.
func (r *ring) writev(fd int, bufs [][]byte) (int, error) {
	if r.closed.Load() != 0 {
		return 0, ErrClosed
	}
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(bufs) > MaxIovecs {
		return 0, fmt.Errorf("iouring: %d buffers exceeds max %d", len(bufs), MaxIovecs)
	}

	// Build the iovec scratch. Skip zero-length buffers entirely —
	// an iovec with Base=&b[0] where len(b)==0 would panic the
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
	nrVecs := uint32(len(iovs))

	// Acquire an SQE slot. Kernel writes sqHead as it consumes
	// submissions; an acquire-ordered load is required to observe
	// those writes correctly.
	head := atomic.LoadUint32(r.sqHead)
	tail := atomic.LoadUint32(r.sqTail) // plain load of our own writes; use atomic for -race cleanliness
	mask := *r.sqMask                   // immutable post-setup
	if tail-head >= r.sqEntries {
		return 0, ErrSQFull
	}
	idx := tail & mask
	sqe := &r.sqesView[idx]

	// Fill the SQE with plain stores. These happen-before the
	// atomic.StoreUint32 on sqTail below, so the kernel observes
	// a fully-populated SQE when it sees the new tail value.
	*sqe = ioUringSqe{} // zero first — previous iteration may have left residue
	sqe.OpCode = ioringOpWritev
	sqe.Fd = int32(fd)
	sqe.Off = ^uint64(0) // O_APPEND sentinel
	sqe.Addr = uint64(uintptr(unsafe.Pointer(&iovs[0])))
	sqe.Len = nrVecs

	// Release-store the new tail. Publishes the SQE to the kernel.
	atomic.StoreUint32(r.sqTail, tail+1)

	// Submit and wait. Retry EINTR unbounded (signals are routine);
	// retry EAGAIN bounded (wedged kernel).
	eagainRetries := 0
	for {
		_, err := ioUringEnter(r.fd, 1, 1, ioringEnterGetEvents)
		if err == nil {
			break
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) && eagainRetries < maxEAGAINRetries {
			eagainRetries++
			continue
		}
		// Pin the iovec scratch and the caller's backing arrays
		// across the failed enter as well — the kernel may have
		// already queued the SQE before returning an error.
		runtime.KeepAlive(iovs)
		runtime.KeepAlive(bufs)
		return 0, fmt.Errorf("iouring: io_uring_enter: %w", err)
	}

	// Pin the iovec scratch and the caller's backing arrays across
	// the kernel's read of the iovec memory. Required on kernels
	// that do not advertise IORING_FEAT_SUBMIT_STABLE (absent on
	// 5.4; present on 5.5+). See project_iouring_research.md.
	runtime.KeepAlive(iovs)
	runtime.KeepAlive(bufs)

	// Consume the CQE. cqTail is written by the kernel (release);
	// an acquire load pairs with that release.
	cqTail := atomic.LoadUint32(r.cqTail)
	cqHead := atomic.LoadUint32(r.cqHead)
	if cqHead == cqTail {
		// Kernel returned from enter without posting a CQE — a bug.
		return 0, fmt.Errorf("iouring: enter returned but no CQE posted (kernel bug)")
	}
	cqMask := *r.cqMask
	cqe := &r.cqesView[cqHead&cqMask]
	res := cqe.Res
	// Release-store the new cqHead so the kernel can reuse the slot.
	atomic.StoreUint32(r.cqHead, cqHead+1)

	if res < 0 {
		return 0, syscall.Errno(-res)
	}
	return int(res), nil
}
