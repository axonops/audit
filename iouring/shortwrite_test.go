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
	"syscall"
	"testing"
)

// TestShortWrite_Pipe fills a non-blocking pipe with more bytes
// than its buffer can hold and asserts the library reports a
// short write via (n, nil) rather than wrapping it as an
// error — matching the writev(2) contract.
//
// The test uses syscall.Pipe2 directly to avoid [os.File.Fd]
// silently switching the fd back to blocking mode (see Go issue
// tracker: os.File.Fd disables runtime-poller on the descriptor).
func TestShortWrite_Pipe(t *testing.T) {
	skipIfNotUnix(t)

	for _, tc := range []struct {
		name  string
		force Strategy
	}{
		{"writev", StrategyWritev},
		{"auto", StrategyAuto},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fds [2]int
			if err := syscall.Pipe2(fds[:], syscall.O_NONBLOCK|syscall.O_CLOEXEC); err != nil {
				t.Fatalf("pipe2: %v", err)
			}
			readFd, writeFd := fds[0], fds[1]
			defer func() {
				_ = syscall.Close(readFd)
				_ = syscall.Close(writeFd)
			}()

			writer, err := New(WithStrategy(tc.force))
			if err != nil {
				t.Fatalf("New(%s): %v", tc.force, err)
			}
			defer func() { _ = writer.Close() }()

			// A 96 KiB payload easily exceeds Linux's 64 KiB
			// default pipe capacity — the kernel accepts as much
			// as fits and returns the short count, or returns
			// EAGAIN when the pipe is already full.
			payload := make([]byte, 96*1024)
			for i := range payload {
				payload[i] = byte('A' + (i % 26))
			}

			n, err := writer.Write(writeFd, payload)
			switch {
			case err == nil:
				// Short write contract: kernel wrote some bytes,
				// may be < len(payload). Regression: if the
				// library began wrapping short writes as errors,
				// this branch would not be taken.
				if n <= 0 {
					t.Fatalf("Writev reported n=%d with nil error; want >0", n)
				}
				if n > len(payload) {
					t.Fatalf("Writev reported n=%d > payload len %d", n, len(payload))
				}
			case errors.Is(err, syscall.EAGAIN):
				// Pipe was already full (e.g. kernel book-keeping
				// has not yet advanced). Acceptable — the library
				// surfaced the errno unwrapped so the caller can
				// match it.
				if n != 0 {
					t.Errorf("EAGAIN with n=%d, want 0", n)
				}
			default:
				t.Fatalf("unexpected (n=%d, err=%v)", n, err)
			}

			// Drain enough bytes that the OS-pipe cleanup doesn't
			// block on close. Non-blocking read; may short-read.
			if n > 0 {
				drain := make([]byte, n)
				_, _ = syscall.Read(readFd, drain)
			}
		})
	}
}
