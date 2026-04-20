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

package iouring_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/axonops/audit/iouring"
)

// benchFile returns a freshly-created O_APPEND|O_WRONLY file.
// The file is truncated-on-open so benchmarks start from a
// predictable state. Uses /dev/shm when available to isolate
// syscall overhead from device-write cost.
func benchFile(tb testing.TB) *os.File {
	tb.Helper()
	dir := "/dev/shm"
	if _, err := os.Stat(dir); err != nil {
		dir = tb.TempDir()
	}
	path := filepath.Join(dir, fmt.Sprintf("iouring-bench-%d.log", os.Getpid()))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		_ = f.Close()
		_ = os.Remove(path)
	})
	return f
}

// makeBatch allocates a reusable batch of nBufs × eventSize.
// Each event is a distinct []byte; the batch itself is the
// `bufs` argument to Writev.
func makeBatch(nBufs, eventSize int) [][]byte {
	batch := make([][]byte, nBufs)
	for i := range batch {
		b := make([]byte, eventSize)
		for j := range b {
			b[j] = byte('A' + (j % 26))
		}
		b[eventSize-1] = '\n'
		batch[i] = b
	}
	return batch
}

// batchSizes defines the horizontal axis for the parametric
// benchmarks. The crossover where io_uring beats syscall.writev
// is typically at batch >= 64 on modern kernels; include a
// range so the curve is visible in benchstat output.
var batchSizes = []int{1, 4, 16, 64, 256, 1024}

// BenchmarkWriter_Writev measures single-writer throughput at
// varying batch sizes under each strategy. Run via:
//
//	go test -bench BenchmarkWriter_Writev -benchmem
func BenchmarkWriter_Writev(b *testing.B) {
	const eventSize = 256

	for _, strat := range []iouring.Strategy{iouring.StrategyIouring, iouring.StrategyWritev} {
		if strat == iouring.StrategyIouring && !iouring.IouringSupported() {
			continue
		}
		b.Run(strat.String(), func(b *testing.B) {
			for _, n := range batchSizes {
				b.Run(fmt.Sprintf("batch_%d", n), func(b *testing.B) {
					w, err := iouring.New(iouring.WithStrategy(strat))
					if err != nil {
						b.Fatalf("New(%s): %v", strat, err)
					}
					defer func() { _ = w.Close() }()
					f := benchFile(b)
					fd := int(f.Fd())
					batch := makeBatch(n, eventSize)

					b.ReportAllocs()
					b.SetBytes(int64(n * eventSize))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if _, err := w.Writev(fd, batch); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

// BenchmarkPackage_Writev_Concurrent measures package-level
// Writev under parallel callers to expose the default-writer
// mutex cost.
func BenchmarkPackage_Writev_Concurrent(b *testing.B) {
	f := benchFile(b)
	fd := int(f.Fd())
	batch := makeBatch(8, 256)

	b.ReportAllocs()
	b.SetBytes(int64(8 * 256))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := iouring.Writev(fd, batch); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkWriter_Writev_OwnInstance measures one Writer per
// producer (no mutex contention on the default writer) to
// provide a contrast with BenchmarkPackage_Writev_Concurrent.
func BenchmarkWriter_Writev_OwnInstance(b *testing.B) {
	f := benchFile(b)
	fd := int(f.Fd())
	batch := makeBatch(8, 256)

	b.ReportAllocs()
	b.SetBytes(int64(8 * 256))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w, err := iouring.New()
		if err != nil {
			b.Fatal(err)
		}
		defer func() { _ = w.Close() }()
		var mu sync.Mutex // serialise this goroutine's own writes
		for pb.Next() {
			mu.Lock()
			_, err := w.Writev(fd, batch)
			mu.Unlock()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
