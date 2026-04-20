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
	"runtime"
	"syscall"
	"unsafe"
)

// Linux syscall numbers for io_uring. Identical on amd64 and arm64
// via the unified syscall-number table (5.1+). Other architectures
// are not supported in v1.0 — ring_other.go catches those at
// compile time via the !linux build tag; within Linux, only amd64
// and arm64 are in our CI matrix.
const (
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427
)

// mmap protection and flag constants. Matching values to
// /usr/include/bits/mman-linux.h to keep the call self-contained
// (no golang.org/x/sys dependency).
const (
	_PROT_READ  = 0x1
	_PROT_WRITE = 0x2
	_MAP_SHARED = 0x01
)

// ioUringSetup invokes the io_uring_setup syscall. The params
// argument receives kernel-computed offsets and feature flags on
// success. Returns the ring fd or an error.
//
// runtime.KeepAlive(params) is called after the syscall returns:
// although the kernel writes to *params synchronously during setup,
// the compiler may reorder the address-taking; KeepAlive guarantees
// the backing memory survives the whole call unconditionally.
func ioUringSetup(entries uint32, params *ioUringParams) (int, error) {
	r1, _, errno := syscall.Syscall(
		sysIoUringSetup,
		uintptr(entries),
		uintptr(unsafe.Pointer(params)),
		0,
	)
	runtime.KeepAlive(params)
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

// ioUringEnter invokes the io_uring_enter syscall. sig must be nil
// in v1.0 (no signal-mask support); sigSize must be 0 in that case.
// Returns the number of submitted SQEs on success, or an error.
func ioUringEnter(fd int, toSubmit, minComplete uint32, flags uint32) (int, error) {
	r1, _, errno := syscall.Syscall6(
		sysIoUringEnter,
		uintptr(fd),
		uintptr(toSubmit),
		uintptr(minComplete),
		uintptr(flags),
		0, // sig
		0, // sigSize
	)
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

// sysMmapRaw invokes mmap for a shared, read/write mapping of a
// ring region at the given offset from fd. It delegates to the
// stdlib [syscall.Mmap] wrapper which returns a []byte view over
// the kernel-owned mapping. Using the stdlib wrapper keeps the
// vet-safe `&b[i]` pattern available for subsequent field
// accesses.
func sysMmapRaw(fd int, offset int64, length int) ([]byte, error) {
	return syscall.Mmap(fd, offset, length, _PROT_READ|_PROT_WRITE, _MAP_SHARED)
}

// sysMunmap invokes munmap on a previously mmap'd region.
func sysMunmap(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Munmap(b)
}
