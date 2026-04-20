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

import "unsafe"

// mmap offsets for io_uring regions.
// Kernel ref: include/uapi/linux/io_uring.h
const (
	ioringOffSQRing = 0
	ioringOffCQRing = 0x8000000
	ioringOffSQEs   = 0x10000000
)

// io_uring_setup flags (unused in v1.0; listed for completeness).
const (
	_ = 1 << iota // IORING_SETUP_IOPOLL
	_             // IORING_SETUP_SQPOLL
)

// io_uring feature flags reported by the kernel in
// io_uring_params.Features after a successful setup.
const (
	ioringFeatSingleMMap = 1 << 0 // kernel 5.4
	ioringFeatNoDrop     = 1 << 1 // kernel 5.5 — required by this package
)

// io_uring_enter flags.
const (
	ioringEnterGetEvents = 1 << 0
)

// Opcodes (v1.0 exports writev only). Values match the kernel's
// linux/io_uring.h enum io_uring_op. IORING_OP_NOP=0,
// IORING_OP_READV=1, IORING_OP_WRITEV=2.
const (
	ioringOpWritev uint8 = 2
)

// ioSqringOffsets maps the kernel's struct io_sqring_offsets exactly.
type ioSqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	Resv2       uint64
}

// ioCqringOffsets maps the kernel's struct io_cqring_offsets exactly.
type ioCqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	CQEs        uint32
	Flags       uint32
	Resv1       uint32
	Resv2       uint64
}

// ioUringParams is the parameter block for io_uring_setup and the
// reply carrier for kernel-advertised feature flags and ring-offset
// information. Layout must match the kernel's struct io_uring_params
// exactly (88 bytes on 5.4+).
type ioUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        ioSqringOffsets
	CqOff        ioCqringOffsets
}

// ioUringSqe is the kernel's submission queue entry. Layout must
// match struct io_uring_sqe exactly — 64 bytes on 5.4+. A compile-
// time assertion below checks the size.
type ioUringSqe struct {
	OpCode      uint8
	Flags       uint8
	IoPrio      uint16
	Fd          int32
	Off         uint64 // union: offset / addr2
	Addr        uint64 // union: addr / splice_off_in
	Len         uint32
	OpFlags     uint32 // union: rw_flags / fsync_flags / ...
	UserData    uint64
	BufIndex    uint16 // union: buf_index / buf_group
	Personality uint16
	SpliceFdIn  int32 // union: splice_fd_in / file_index
	Pad         [2]uint64
}

// ioUringCqe is the kernel's completion queue entry. Layout must
// match struct io_uring_cqe exactly — 16 bytes. A compile-time
// assertion below checks the size.
type ioUringCqe struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

// Compile-time size assertions. If the kernel ever changes these
// sizes we want a build break, not a runtime memory-corruption bug.
// The negative-length array trick fails to compile if sizeof(T)
// differs from the expected value.
var (
	_ [0]byte = [unsafe.Sizeof(ioUringSqe{}) - 64]byte{}
	_ [0]byte = [64 - unsafe.Sizeof(ioUringSqe{})]byte{}
	_ [0]byte = [unsafe.Sizeof(ioUringCqe{}) - 16]byte{}
	_ [0]byte = [16 - unsafe.Sizeof(ioUringCqe{})]byte{}
)
