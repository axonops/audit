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
	"log/slog"
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

// skipIfNotUnix skips the test on platforms where New() returns
// ErrUnsupported (currently Windows).
func skipIfNotUnix(t *testing.T) {
	t.Helper()
	if _, err := New(); errors.Is(err, ErrUnsupported) {
		t.Skipf("iouring.New(): ErrUnsupported on %s", runtime.GOOS)
	}
}

// containsStr is a local mini-strings.Contains to avoid a
// strings-package dependency in tests.
func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------
// Strategy enum
// ---------------------------------------------------------------

func TestStrategy_String(t *testing.T) {
	cases := map[Strategy]string{
		StrategyAuto:    "auto",
		StrategyIouring: "iouring",
		StrategyWritev:  "writev",
		Strategy(99):    "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Strategy(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// ---------------------------------------------------------------
// New / options
// ---------------------------------------------------------------

func TestNew_DefaultStrategyPicksSomethingUsable(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()
	s := w.Strategy()
	if s != StrategyIouring && s != StrategyWritev {
		t.Fatalf("Strategy() = %s, want iouring or writev", s)
	}
}

func TestNew_ForceWritevOnCapableHost(t *testing.T) {
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

func TestNew_ForceIouringFailsOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux supports io_uring; tested elsewhere")
	}
	_, err := New(WithStrategy(StrategyIouring))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want wraps ErrUnsupported", err)
	}
}

func TestNew_InvalidStrategyValue(t *testing.T) {
	skipIfNotUnix(t)
	_, err := New(WithStrategy(Strategy(99)))
	if err == nil {
		t.Fatal("expected error for invalid Strategy")
	}
	if !containsStr(err.Error(), "invalid Strategy value") {
		t.Fatalf("err message = %q, want contains 'invalid Strategy value'", err.Error())
	}
}

func TestWithRingDepth_Valid(t *testing.T) {
	skipIfNotUnix(t)
	for _, n := range []uint32{1, 2, 4, 16, 64, 256, 1024, 4096} {
		w, err := New(WithRingDepth(n))
		if err != nil {
			t.Errorf("WithRingDepth(%d): %v", n, err)
			continue
		}
		_ = w.Close()
	}
}

func TestWithRingDepth_Invalid(t *testing.T) {
	// Invalid ring depth is a programmer error surfaced by the
	// option itself; runs on every platform since New never
	// reaches strategy selection when the option has stored an
	// error.
	cases := []uint32{0, 3, 5, 6, 7, 4097, 8192, 65535}
	for _, n := range cases {
		_, err := New(WithRingDepth(n))
		if err == nil {
			t.Errorf("WithRingDepth(%d): no error", n)
			continue
		}
		if !containsStr(err.Error(), "power of two in [1, 4096]") {
			t.Errorf("WithRingDepth(%d): err = %q, want contains 'power of two in [1, 4096]'", n, err.Error())
		}
	}
}

func TestWithLogger_EmitsOneLineAtConstruction(t *testing.T) {
	skipIfNotUnix(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	w, err := New(WithLogger(logger))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = w.Close() }()

	// One line at construction.
	lines := bytes.Count(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n")) + 1
	if buf.Len() == 0 {
		t.Fatal("logger received no output")
	}
	if lines != 1 {
		t.Errorf("got %d log lines at construction, want 1", lines)
	}
	// Message must carry the negotiated strategy.
	if !containsStr(buf.String(), w.Strategy().String()) {
		t.Errorf("log line missing strategy %q: %s", w.Strategy(), buf.String())
	}

	// Hot path must be silent — subsequent Writev emits no log.
	before := buf.Len()
	f, _ := openAppendFile(t)
	defer func() { _ = f.Close() }()
	_, _ = w.Writev(int(f.Fd()), [][]byte{[]byte("x\n")})
	if buf.Len() != before {
		t.Errorf("logger saw output on hot path: %q", buf.String()[before:])
	}
}

// ---------------------------------------------------------------
// Writer.Writev — roundtrip (runs under whichever strategy New picks)
// ---------------------------------------------------------------

func TestWriter_WriteRoundtrip(t *testing.T) {
	skipIfNotUnix(t)
	for _, tc := range []struct {
		name  string
		force Strategy
	}{
		{"auto", StrategyAuto},
		{"writev", StrategyWritev},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.force != StrategyAuto {
				opts = append(opts, WithStrategy(tc.force))
			}
			w, err := New(opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = w.Close() }()

			f, path := openAppendFile(t)
			defer func() { _ = f.Close() }()

			payload := []byte("hello writer\n")
			n, err := w.Write(int(f.Fd()), payload)
			if err != nil {
				t.Fatalf("Write: %v", err)
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
		})
	}
}

func TestWriter_Writev_MultipleBufs(t *testing.T) {
	skipIfNotUnix(t)
	for _, tc := range []struct {
		name  string
		force Strategy
	}{
		{"auto", StrategyAuto},
		{"writev", StrategyWritev},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.force != StrategyAuto {
				opts = append(opts, WithStrategy(tc.force))
			}
			w, err := New(opts...)
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
				t.Fatalf("Writev: %v", err)
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
		})
	}
}

func TestWriter_EmptyAndNilBufs(t *testing.T) {
	skipIfNotUnix(t)
	for _, tc := range []struct {
		name  string
		force Strategy
	}{
		{"auto", StrategyAuto},
		{"writev", StrategyWritev},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.force != StrategyAuto {
				opts = append(opts, WithStrategy(tc.force))
			}
			w, err := New(opts...)
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
		})
	}
}

func TestWriter_EmptyInnerBufsSkipped(t *testing.T) {
	skipIfNotUnix(t)
	for _, tc := range []struct {
		name  string
		force Strategy
	}{
		{"auto", StrategyAuto},
		{"writev", StrategyWritev},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.force != StrategyAuto {
				opts = append(opts, WithStrategy(tc.force))
			}
			w, err := New(opts...)
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
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, []byte("abc")) {
				t.Fatalf("file = %q, want %q", got, "abc")
			}
		})
	}
}

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

func TestWriter_InvalidFd(t *testing.T) {
	// Negative or oversized fd rejected by the library before
	// reaching the kernel. Runs on both strategies.
	skipIfNotUnix(t)
	for _, tc := range []struct {
		name  string
		force Strategy
		fd    int
	}{
		{"auto/negative", StrategyAuto, -2},
		{"writev/negative", StrategyWritev, -2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(WithStrategy(tc.force))
			if err != nil {
				t.Skipf("strategy %s unavailable: %v", tc.force, err)
			}
			defer func() { _ = w.Close() }()
			_, err = w.Writev(tc.fd, [][]byte{[]byte("x")})
			if err == nil {
				t.Fatalf("expected error for fd=%d", tc.fd)
			}
		})
	}
}

// ---------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------

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
	if _, err := w.Write(0, []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

func TestWriter_DoubleCloseConcurrent(t *testing.T) {
	skipIfNotUnix(t)
	w, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 4)
	wg.Add(len(errs))
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			errs[i] = w.Close()
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("goroutine %d Close: %v", i, e)
		}
	}
}

// ---------------------------------------------------------------
// Package-level Writev
// ---------------------------------------------------------------

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
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, payload) {
		t.Fatalf("file = %q, want %q", got, payload)
	}
}

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
				if _, err := Writev(int(f.Fd()), [][]byte{[]byte("x\n")}); err != nil {
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

// ---------------------------------------------------------------
// IouringSupported probe
// ---------------------------------------------------------------

func TestIouringSupported_PlatformConsistent(t *testing.T) {
	got := IouringSupported()
	if runtime.GOOS != "linux" && got {
		t.Fatalf("IouringSupported() = true on %s, want false", runtime.GOOS)
	}
}
