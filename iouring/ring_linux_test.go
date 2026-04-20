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
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

// TestSQECQESizes pins the kernel-ABI struct sizes. These are
// verified at compile time via the negative-length-array trick
// in types_linux.go; this test is the runtime documentation pin
// that a future arch port can diff against.
func TestSQECQESizes(t *testing.T) {
	if got := unsafe.Sizeof(ioUringSqe{}); got != 64 {
		t.Errorf("sizeof(ioUringSqe) = %d, want 64", got)
	}
	if got := unsafe.Sizeof(ioUringCqe{}); got != 16 {
		t.Errorf("sizeof(ioUringCqe) = %d, want 16", got)
	}
}

// TestRing_UserDataMonotonic is a white-box regression guard
// for the CQE-scan fix. Each ring.writev tags its SQE with an
// incrementing UserData counter. If a future refactor removes
// or breaks the tagging, this fails fast.
func TestRing_UserDataMonotonic(t *testing.T) {
	if !IouringSupported() {
		t.Skip("io_uring unavailable on this host")
	}
	w, err := New(WithStrategy(StrategyIouring))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	impl := w.impl.(*iouringStrategy)
	if impl.r.userDataCounter != 0 {
		t.Fatalf("userDataCounter = %d at init, want 0", impl.r.userDataCounter)
	}

	// Issue N writes. Counter should land at N.
	f, _ := openAppendFile(t)
	defer func() { _ = f.Close() }()

	const N = 5
	for i := 0; i < N; i++ {
		if _, err := w.Write(int(f.Fd()), []byte("x\n")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if impl.r.userDataCounter != uint64(N) {
		t.Errorf("userDataCounter = %d after %d writes, want %d", impl.r.userDataCounter, N, N)
	}
}

// TestRing_StressRoundTrip runs many iouring writes and confirms
// byte counts line up. This is the pattern that surfaced the
// original CQE-reorder bug via ~1-in-30 failures. Kept at a
// modest N so normal `go test` is quick; `go test -count=N`
// provides the stress knob.
func TestRing_StressRoundTrip(t *testing.T) {
	if !IouringSupported() {
		t.Skip("io_uring unavailable on this host")
	}
	w, err := New(WithStrategy(StrategyIouring))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	path := filepath.Join(t.TempDir(), "stress.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = f.Close() }()

	const rounds = 512
	const payload = "stress-line-of-bytes-to-write\n"
	for i := 0; i < rounds; i++ {
		n, err := w.Write(int(f.Fd()), []byte(payload))
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if n != len(payload) {
			t.Fatalf("round %d: n=%d want %d", i, n, len(payload))
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(rounds*len(payload)) {
		t.Fatalf("file size = %d, want %d", info.Size(), rounds*len(payload))
	}
}

// TestSameBacking covers the SINGLE_MMAP detection helper that
// guards against double-munmap on Close. The helper ships on
// every modern kernel (5.4+ sets IORING_FEAT_SINGLE_MMAP) so
// the shared-mapping arm is exercised at runtime, but the
// distinct-mapping arm is path-dead on current kernels — hence
// the unit test.
func TestSameBacking(t *testing.T) {
	a := []byte{1, 2, 3}
	b := a // slice header copy; shares backing.
	c := []byte{1, 2, 3}
	if !sameBacking(a, b) {
		t.Error("sameBacking(a, a) = false, want true")
	}
	if sameBacking(a, c) {
		t.Error("sameBacking(a, c) = true, want false (distinct arrays)")
	}
	if sameBacking(nil, a) {
		t.Error("sameBacking(nil, a) = true, want false")
	}
	if sameBacking(a, nil) {
		t.Error("sameBacking(a, nil) = true, want false")
	}
	if sameBacking(nil, nil) {
		t.Error("sameBacking(nil, nil) = true, want false")
	}
}

// TestIsPowerOfTwo covers the helper the entries validator
// relies on. Table-driven, cheap, documents the contract.
func TestIsPowerOfTwo(t *testing.T) {
	cases := []struct {
		n    uint32
		want bool
	}{
		{0, false},
		{1, true}, {2, true}, {4, true}, {8, true}, {16, true},
		{3, false}, {5, false}, {6, false}, {7, false},
		{1024, true}, {1023, false}, {1025, false},
		{1 << 31, true},
		{(1 << 31) + 1, false},
	}
	for _, tc := range cases {
		if got := isPowerOfTwo(tc.n); got != tc.want {
			t.Errorf("isPowerOfTwo(%d) = %v, want %v", tc.n, got, tc.want)
		}
	}
}
