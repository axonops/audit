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
	"sync/atomic"
	"syscall"
	"unsafe"
)

// ring owns all kernel resources backing a [Ring] on Linux.
// It is created by newRing and released by close. All pointer
// fields are either mmap addresses (owned by the kernel mapping)
// or pointers into those mappings; they are not Go-allocated and
// require no GC tracking.
type ring struct {
	// closed gates against double-close and use-after-close. Exactly
	// zero on a live ring, non-zero after Close. atomic.Uint32 CAS
	// on Close prevents the hazard where two concurrent Close calls
	// (a contract violation we nonetheless defend against) both
	// munmap the same region.
	closed atomic.Uint32

	// fd is the io_uring instance file descriptor returned by
	// io_uring_setup. Closed last during teardown.
	fd int

	// Feature flags cached from the kernel's io_uring_params.Features
	// reply; used to decide whether SQ and CQ share a mapping
	// (IORING_FEAT_SINGLE_MMAP) and to assert required features
	// (IORING_FEAT_NODROP, already checked at NewRing time).
	features uint32

	// Mmap regions stored as []byte views over kernel-owned memory
	// — matches the [syscall.Mmap] convention and keeps `go vet`'s
	// unsafeptr analyzer happy. On kernels with IORING_FEAT_SINGLE_MMAP
	// (5.4+), cqRing aliases sqRing; Close compares the backing
	// array pointers before unmapping to avoid double-munmap.
	sqRing []byte
	cqRing []byte
	sqes   []byte

	// Ring-index pointers. Each points into one of the mmap'd
	// regions; reads and writes go through atomic.Load/Store
	// wrappers for memory-ordering correctness against the kernel
	// side of the queues.
	sqHead  *uint32
	sqTail  *uint32
	sqMask  *uint32
	sqArray *uint32 // base of SQ index array; length = sqEntries

	cqHead *uint32
	cqTail *uint32
	cqMask *uint32

	// sqesView and cqesView are typed views over the mmap regions.
	// sqesView is backed by the sqes mapping; cqesView is backed by
	// the cqRing mapping at the CqOff.CQEs offset.
	sqesView []ioUringSqe
	cqesView []ioUringCqe

	// Capacity for SQ / CQ (may differ when the kernel double-sizes
	// the CQ). sqEntries is used for the SQ index array identity
	// init.
	sqEntries uint32

	// iovScratch is a pre-allocated iovec scratch slice sized to
	// MaxIovecs. Reused across Writev calls. Keeps the hot path
	// alloc-free.
	iovScratch []syscall.Iovec
}

// newRing constructs a Linux ring. It:
//  1. validates entries (power of two, 1..4096);
//  2. invokes io_uring_setup;
//  3. rejects kernels without IORING_FEAT_NODROP (wraps ErrUnsupported);
//  4. marks the ring fd close-on-exec;
//  5. mmaps the SQ ring, CQ ring (when not SINGLE_MMAP), and SQE array;
//  6. computes the ring-index pointers;
//  7. performs the SQ array identity init;
//  8. pre-allocates the iovec scratch.
//
// On any error after io_uring_setup succeeds, the partial state is
// unwound before returning.
func newRing(entries uint32) (*ring, error) {
	if entries == 0 || entries > 4096 || !isPowerOfTwo(entries) {
		return nil, fmt.Errorf("iouring: entries must be a power of two in [1, 4096] (got %d)", entries)
	}

	var params ioUringParams
	fd, err := ioUringSetup(entries, &params)
	if err != nil {
		// Distinguish "kernel too old" (ENOSYS) from other failures.
		if errors.Is(err, syscall.ENOSYS) {
			return nil, fmt.Errorf("iouring: io_uring_setup: %w", ErrUnsupported)
		}
		return nil, fmt.Errorf("iouring: io_uring_setup: %w", err)
	}

	// Require IORING_FEAT_NODROP (5.5+). Without it, a full CQ
	// silently drops completions — an unacceptable audit-integrity
	// failure mode.
	if params.Features&ioringFeatNoDrop == 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("iouring: kernel lacks IORING_FEAT_NODROP: %w", ErrUnsupported)
	}

	// Mark the ring fd close-on-exec so a fork+exec by another
	// goroutine does not leak the fd into child processes. Note
	// there is a narrow window between io_uring_setup and this
	// call; the stdlib's syscall.CloseOnExec has the same window.
	syscall.CloseOnExec(fd)

	r := &ring{
		fd:        fd,
		features:  params.Features,
		sqEntries: params.SqEntries,
	}

	// Mmap the SQ ring region. With IORING_FEAT_SINGLE_MMAP (all
	// 5.4+ kernels) one mapping covers both SQ and CQ rings; size
	// it to the larger of the two projections.
	sqRingSize := int(params.SqOff.Array) + int(params.SqEntries)*int(unsafe.Sizeof(uint32(0)))
	cqEnd := int(params.CqOff.CQEs) + int(params.CqEntries)*int(unsafe.Sizeof(ioUringCqe{}))
	if cqEnd > sqRingSize {
		// SINGLE_MMAP: one mapping covers both rings; size it to the
		// larger of the two projected sizes.
		sqRingSize = cqEnd
	}
	r.sqRing, err = sysMmapRaw(fd, ioringOffSQRing, sqRingSize)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("iouring: mmap SQ ring: %w", err)
	}

	// Either share the mapping with the CQ ring (SINGLE_MMAP) or
	// map the CQ ring separately.
	if params.Features&ioringFeatSingleMMap != 0 {
		r.cqRing = r.sqRing
	} else {
		r.cqRing, err = sysMmapRaw(fd, ioringOffCQRing, cqEnd)
		if err != nil {
			_ = sysMunmap(r.sqRing)
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("iouring: mmap CQ ring: %w", err)
		}
	}

	// Mmap the SQE array.
	sqesSize := int(params.SqEntries) * int(unsafe.Sizeof(ioUringSqe{}))
	r.sqes, err = sysMmapRaw(fd, ioringOffSQEs, sqesSize)
	if err != nil {
		_ = sysMunmap(r.sqRing)
		if !sameBacking(r.cqRing, r.sqRing) {
			_ = sysMunmap(r.cqRing)
		}
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("iouring: mmap SQEs: %w", err)
	}

	// Resolve ring-index pointers. Each is a *uint32 at a computed
	// offset into the relevant mapping. &slice[offset] is bounds-
	// checked and vet-safe.
	r.sqHead = (*uint32)(unsafe.Pointer(&r.sqRing[params.SqOff.Head]))
	r.sqTail = (*uint32)(unsafe.Pointer(&r.sqRing[params.SqOff.Tail]))
	r.sqMask = (*uint32)(unsafe.Pointer(&r.sqRing[params.SqOff.RingMask]))
	r.sqArray = (*uint32)(unsafe.Pointer(&r.sqRing[params.SqOff.Array]))
	r.cqHead = (*uint32)(unsafe.Pointer(&r.cqRing[params.CqOff.Head]))
	r.cqTail = (*uint32)(unsafe.Pointer(&r.cqRing[params.CqOff.Tail]))
	r.cqMask = (*uint32)(unsafe.Pointer(&r.cqRing[params.CqOff.RingMask]))

	// Build typed slice views over the SQE and CQE arrays.
	r.sqesView = unsafe.Slice((*ioUringSqe)(unsafe.Pointer(&r.sqes[0])), int(params.SqEntries))
	r.cqesView = unsafe.Slice(
		(*ioUringCqe)(unsafe.Pointer(&r.cqRing[params.CqOff.CQEs])),
		int(params.CqEntries),
	)

	// SQ array identity init. Without this, every submission
	// reads slot 0 and the kernel processes the wrong SQE.
	sqArraySlice := unsafe.Slice(r.sqArray, int(params.SqEntries))
	for i := uint32(0); i < params.SqEntries; i++ {
		sqArraySlice[i] = i
	}

	// Pre-allocate the iovec scratch. Sized to MaxIovecs so any
	// valid Writev fits without growth.
	r.iovScratch = make([]syscall.Iovec, 0, MaxIovecs)

	return r, nil
}

// close releases all kernel resources backing the ring. Idempotent;
// guarded by an atomic CAS so a racing second caller returns nil.
func (r *ring) close() error {
	if !r.closed.CompareAndSwap(0, 1) {
		return nil
	}

	var firstErr error
	// munmap order: SQEs first, then CQ (if distinct), then SQ.
	if r.sqes != nil {
		if err := sysMunmap(r.sqes); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("iouring: munmap SQEs: %w", err)
		}
		r.sqes = nil
	}
	if r.cqRing != nil && !sameBacking(r.cqRing, r.sqRing) {
		if err := sysMunmap(r.cqRing); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("iouring: munmap CQ ring: %w", err)
		}
	}
	r.cqRing = nil
	if r.sqRing != nil {
		if err := sysMunmap(r.sqRing); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("iouring: munmap SQ ring: %w", err)
		}
		r.sqRing = nil
	}
	if r.fd >= 0 {
		if err := syscall.Close(r.fd); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("iouring: close ring fd: %w", err)
		}
		r.fd = -1
	}
	return firstErr
}

// isPowerOfTwo reports whether n is exactly a power of two. Zero
// is not considered a power of two for our purposes.
func isPowerOfTwo(n uint32) bool {
	return n > 0 && (n&(n-1)) == 0
}

// sameBacking reports whether two byte slices share the same
// backing array — used to detect the SINGLE_MMAP case where
// cqRing aliases sqRing, so Close does not double-munmap.
func sameBacking(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return &a[0] == &b[0]
}
