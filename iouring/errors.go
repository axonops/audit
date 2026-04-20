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

package iouring

import "errors"

// MaxIovecs is the maximum number of buffers accepted by a single
// [Writev] / [Writer.Writev] call. It matches the cross-Unix POSIX
// minimum — Linux `UIO_MAXIOV`, Darwin/FreeBSD/NetBSD/OpenBSD
// `IOV_MAX` — each defined as 1024. Callers batching more buffers
// must split the batch across multiple calls.
const MaxIovecs = 1024

// Sentinel errors returned by the package. Kernel errors (for
// example [syscall.EAGAIN], [syscall.EBADF]) are returned
// unwrapped so callers can match them with [errors.Is]; the
// sentinels below identify library-originated conditions.
var (
	// ErrUnsupported is returned when no vectored-write strategy
	// is available on the current platform, or when a caller
	// explicitly requests a strategy that is unavailable here.
	// Platform causes include:
	//   - non-Unix platforms (Windows) — no writev primitive;
	//   - [WithStrategy]([StrategyIouring]) on a non-Linux host;
	//   - [WithStrategy]([StrategyIouring]) on a Linux kernel
	//     older than 5.5 or without IORING_FEAT_NODROP.
	ErrUnsupported = errors.New("iouring: vectored I/O not supported on this platform")

	// ErrClosed is returned when an operation is attempted on a
	// [Writer] that has already been closed. The package-level
	// [Writev] never returns ErrClosed; it returns [ErrUnsupported]
	// instead if the platform has no vectored-write support.
	ErrClosed = errors.New("iouring: writer is closed")
)
