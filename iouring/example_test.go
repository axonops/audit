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

package iouring_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/axonops/audit/iouring"
)

// Zero-ceremony: use the package-level Writev with a lazily-
// initialised default Writer. Safe for concurrent use.
func ExampleWritev() {
	// Create an append-mode file to write to.
	path := filepath.Join(os.TempDir(), "iouring-example.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(path)
	}()

	// Writev takes int, not uintptr — cast the os.File fd.
	n, err := iouring.Writev(int(f.Fd()), [][]byte{
		[]byte("hello "),
		[]byte("io_uring\n"),
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("wrote", n, "bytes")
	// Output: wrote 15 bytes
}

// Explicit Writer: construct your own instance when you want a
// dedicated logger, a forced strategy, or to avoid contending
// on the default writer's mutex.
func ExampleWriter_Writev() {
	// Force the syscall.writev path for reproducibility.
	w, err := iouring.New(iouring.WithStrategy(iouring.StrategyWritev))
	if err != nil {
		panic(err)
	}
	defer func() { _ = w.Close() }()

	path := filepath.Join(os.TempDir(), "iouring-example-writer.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(path)
	}()

	if _, err := w.Writev(int(f.Fd()), [][]byte{[]byte("one\n"), []byte("two\n")}); err != nil {
		panic(err)
	}

	got, _ := os.ReadFile(path)
	fmt.Print(string(got))
	// Output:
	// one
	// two
}
