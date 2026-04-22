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

package file_test

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axonops/audit/file"
)

// TestFile_SetDiagnosticLoggerUnderEventLoad drives SetDiagnosticLogger
// and Write concurrently to prove the logger field is safe under the
// race detector. Closes #474 AC #3.
//
// Lives in file_external_test.go (not file_test.go) per the explicit
// file-naming acceptance criterion in #474 Testing Requirements.
// Per-test goleak.VerifyNone(t) complements the package-level
// goleak.VerifyTestMain to catch leaks originating in this test's
// goroutines.
func TestFile_SetDiagnosticLoggerUnderEventLoad(t *testing.T) {
	dir := t.TempDir()
	out, err := file.New(&file.Config{
		Path:       filepath.Join(dir, "race.log"),
		BufferSize: 1000,
	}, nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	const iters = 100
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range iters {
			out.SetDiagnosticLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
		}
	}()
	go func() {
		defer wg.Done()
		for range iters {
			_ = out.Write([]byte(`{"event":"race"}` + "\n"))
		}
	}()
	wg.Wait()

	// Close BEFORE goleak check so the rotate-mill background
	// goroutine has exited by the time we assert no leaks.
	require.NoError(t, out.Close())
	goleak.VerifyNone(t)
}
