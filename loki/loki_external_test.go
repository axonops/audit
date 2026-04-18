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

package loki_test

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
)

// TestLoki_SetDiagnosticLoggerUnderEventLoad drives SetDiagnosticLogger
// and WriteWithMetadata concurrently to prove the logger field is safe
// under the race detector. Closes #474 AC #3.
//
// Lives in loki_external_test.go (not config_test.go) per the explicit
// file-naming acceptance criterion in #474 Testing Requirements.
// Per-test goleak.VerifyNone(t) complements the package-level
// goleak.VerifyTestMain to catch leaks from this test's goroutines
// specifically.
func TestLoki_SetDiagnosticLoggerUnderEventLoad(t *testing.T) {
	out, err := loki.New(&loki.Config{
		URL:                "http://127.0.0.1:3100/loki/api/v1/push",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            1 * time.Second,
		BufferSize:         1000,
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
		meta := audit.EventMetadata{EventType: "race", Severity: 1}
		for range iters {
			_ = out.WriteWithMetadata([]byte(`{"event":"race"}`), meta)
		}
	}()
	wg.Wait()

	// Close BEFORE goleak so the loki batch/flush goroutines have
	// exited by the time we assert no leaks.
	require.NoError(t, out.Close())
	goleak.VerifyNone(t)
}
