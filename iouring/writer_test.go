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

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// openAppendFile creates a fresh O_APPEND|O_WRONLY file and
// returns its *os.File plus the path. Callers close via defer.
func openAppendFile(t *testing.T) (*os.File, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	return f, path
}

// TestStrategy_String pins the lowercase stability contract.
func TestStrategy_String(t *testing.T) {
	cases := map[Strategy]string{
		StrategyAuto:        "auto",
		StrategyIouring:     "iouring",
		StrategyWritev:      "writev",
		StrategyUnsupported: "unsupported",
		Strategy(99):        "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Strategy(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// TestNew_DefaultStrategyPicksSomethingUsable confirms that New()
// without options returns a working Writer on any supported
// platform.
func TestNew_DefaultStrategyPicksSomethingUsable(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer func() { _ = w.Close() }()

	s := w.Strategy()
	if s != StrategyIouring && s != StrategyWritev {
		t.Fatalf("Strategy() = %s, want iouring or writev", s)
	}
}

// TestNew_WithStrategyWritevForced ensures callers can explicitly
// opt out of io_uring on capable hosts.
func TestNew_WithStrategyWritevForced(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New(WithStrategy(StrategyWritev))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()
	if w.Strategy() != StrategyWritev {
		t.Fatalf("Strategy() = %s, want writev", w.Strategy())
	}
}

// TestNew_WithStrategyIouringOnlyFailsOnNonLinux pins the
// "fail-loudly" behaviour required by security-reviewer M4.
// Runs on Darwin/*BSD CI variants; skipped on Linux.
func TestNew_WithStrategyIouringOnlyFailsOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux supports io_uring; tested elsewhere")
	}
	_, err := New(WithStrategy(StrategyIouring))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New(WithStrategy(StrategyIouring)) err = %v, want wraps ErrUnsupported", err)
	}
}

// TestWriter_WriteRoundtrip exercises the happy path through the
// default writer.
func TestWriter_WriteRoundtrip(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	f, path := openAppendFile(t)
	defer func() { _ = f.Close() }()

	payload := []byte("hello writer\n")
	n, err := w.Write(int(f.Fd()), payload)
	if err != nil {
		t.Fatalf("w.Write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("n = %d, want %d", n, len(payload))
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("file contents = %q, want %q", got, payload)
	}
}

// TestWriter_Writev_MultipleBufs verifies iovec-level batching.
func TestWriter_Writev_MultipleBufs(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	f, path := openAppendFile(t)
	defer func() { _ = f.Close() }()

	bufs := [][]byte{[]byte("alpha "), []byte("beta "), []byte("gamma\n")}
	want := []byte("alpha beta gamma\n")

	n, err := w.Writev(int(f.Fd()), bufs)
	if err != nil {
		t.Fatalf("w.Writev: %v", err)
	}
	if n != len(want) {
		t.Fatalf("n = %d, want %d", n, len(want))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file = %q, want %q", got, want)
	}
}

// TestWriter_EmptyAndNilBufs covers the no-op cases that must not
// touch the kernel.
func TestWriter_EmptyAndNilBufs(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	if n, err := w.Writev(-1, nil); n != 0 || err != nil {
		t.Errorf("Writev(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := w.Writev(-1, [][]byte{{}, {}}); n != 0 || err != nil {
		t.Errorf("Writev(all empty) = (%d, %v), want (0, nil)", n, err)
	}
}

// TestWriter_EmptyInnerBufsSkipped confirms zero-length elements
// are silently skipped (security H1).
func TestWriter_EmptyInnerBufsSkipped(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	f, path := openAppendFile(t)
	defer func() { _ = f.Close() }()

	bufs := [][]byte{{}, []byte("a"), {}, []byte("bc"), {}}
	n, err := w.Writev(int(f.Fd()), bufs)
	if err != nil {
		t.Fatalf("Writev: %v", err)
	}
	if n != 3 {
		t.Fatalf("n = %d, want 3", n)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("file = %q, want %q", got, "abc")
	}
}

// TestWriter_MaxIovecsExceeded pins the MaxIovecs cap.
func TestWriter_MaxIovecsExceeded(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	bufs := make([][]byte, MaxIovecs+1)
	for i := range bufs {
		bufs[i] = []byte{'x'}
	}
	if _, err := w.Writev(-1, bufs); err == nil || !containsStr(err.Error(), "exceeds max") {
		t.Fatalf("Writev err = %v, want error containing 'exceeds max'", err)
	}
}

// TestWriter_CloseIdempotent and TestWriter_UseAfterClose cover
// lifecycle correctness.
func TestWriter_CloseIdempotent(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestWriter_UseAfterClose(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = w.Close()
	_, err = w.Write(0, []byte("x"))
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Write after Close err = %v, want ErrClosed", err)
	}
}

func TestWriter_NilReceiverCloseIsSafe(t *testing.T) {
	var w *Writer
	if err := w.Close(); err != nil {
		t.Fatalf("nil Writer Close: %v", err)
	}
}

// TestWriter_DoubleCloseConcurrent covers the race detector path
// for the atomic close CAS (security M1).
func TestWriter_DoubleCloseConcurrent(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = w.Close()
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Errorf("concurrent Close: %v", e)
		}
	}
}

// TestPackageLevel_Writev_RoundTrip covers the Tier-1 zero-
// ceremony entry point.
func TestPackageLevel_Writev_RoundTrip(t *testing.T) {
	skipIfNotUnix(t)
	f, path := openAppendFile(t)
	defer func() { _ = f.Close() }()

	payload := []byte("package-level hi\n")
	n, err := Writev(int(f.Fd()), [][]byte{payload})
	if err != nil {
		t.Fatalf("Writev: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("n = %d, want %d", n, len(payload))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("file = %q, want %q", got, payload)
	}
}

// TestPackageLevel_Write_SingleBuf covers the single-buf shortcut.
func TestPackageLevel_Write_SingleBuf(t *testing.T) {
	skipIfNotUnix(t)
	f, _ := openAppendFile(t)
	defer func() { _ = f.Close() }()

	if _, err := Write(int(f.Fd()), []byte("once")); err != nil {
		t.Fatalf("Write: %v", err)
	}
}

// TestPackageLevel_ConcurrentWriters confirms the internal mutex
// protecting the default writer is sufficient under contention.
func TestPackageLevel_ConcurrentWriters(t *testing.T) {
	skipIfNotUnix(t)
	f, path := openAppendFile(t)
	defer func() { _ = f.Close() }()

	const goroutines, perG = 16, 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				if _, err := Write(int(f.Fd()), []byte("x\n")); err != nil {
					t.Errorf("g=%d i=%d: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(goroutines * perG * 2)
	if info.Size() != want {
		t.Fatalf("file size = %d, want %d", info.Size(), want)
	}
}

// TestDefaultStrategy_ReportsExpected confirms the default-writer
// strategy accessor works post-initialisation.
func TestDefaultStrategy_ReportsExpected(t *testing.T) {
	skipIfNotUnix(t)
	// Force initialisation of the default writer.
	_, _ = Writev(-1, nil)
	s := DefaultStrategy()
	if s != StrategyIouring && s != StrategyWritev {
		t.Fatalf("DefaultStrategy() = %s, want iouring or writev", s)
	}
}

// TestIouringSupported_LinuxTrue asserts true on Linux and false
// elsewhere.
func TestIouringSupported_PlatformConsistent(t *testing.T) {
	got := IouringSupported()
	if runtime.GOOS == "linux" && !got {
		t.Skip("Linux host without io_uring support (old kernel?); Supported() = false")
	}
	if runtime.GOOS != "linux" && got {
		t.Fatalf("IouringSupported() = true on %s, want false", runtime.GOOS)
	}
}

// skipIfNotUnix skips the test on platforms where New() returns
// ErrUnsupported (currently Windows). Keeps the suite green on
// cross-compile targets without masking bugs.
func skipIfNotUnix(t *testing.T) {
	t.Helper()
	if _, err := New(); errors.Is(err, ErrUnsupported) {
		t.Skipf("iouring.New(): ErrUnsupported on %s", runtime.GOOS)
	}
}

// containsStr is the tiny helper mirror of strings.Contains so we
// avoid a strings import bloat when only one test file needs it.
func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
