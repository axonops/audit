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

//go:build unix

package iouring

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// writevStrategy is the portable syscall writev(2) path. Stateless
// — no resources to hold, no Close to implement. Safe on every
// Unix platform (Linux, Darwin, *BSD).
type writevStrategy struct {
	iovScratch []syscall.Iovec
}

func newWritevStrategy() *writevStrategy {
	return &writevStrategy{iovScratch: make([]syscall.Iovec, 0, MaxIovecs)}
}

func (s *writevStrategy) kind() Strategy { return StrategyWritev }
func (s *writevStrategy) close() error   { return nil }

func (s *writevStrategy) writev(fd int, bufs [][]byte) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(bufs) > MaxIovecs {
		return 0, fmt.Errorf("iouring: %d buffers exceeds max %d", len(bufs), MaxIovecs)
	}
	iovs := s.iovScratch[:0]
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

	// Retry EINTR transparently — writev(2) can be interrupted by
	// a signal with no data written.
	for {
		n, _, errno := syscall.Syscall(
			syscall.SYS_WRITEV,
			uintptr(fd),
			uintptr(unsafe.Pointer(&iovs[0])),
			uintptr(len(iovs)),
		)
		runtime.KeepAlive(iovs)
		runtime.KeepAlive(bufs)
		if errno == 0 {
			return int(n), nil
		}
		if errors.Is(errno, syscall.EINTR) {
			continue
		}
		return 0, errno
	}
}
