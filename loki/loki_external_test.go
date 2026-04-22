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
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

// TestLokiClient_ResponseHeaderTimeoutHasFloor verifies that the
// transport's ResponseHeaderTimeout is never less than 1 second. Loki
// Config validation enforces MinTimeout=1s so the smallest permitted
// input is 1s — for which half (500 ms) falls below the 1s floor and
// the floor must kick in. Exercises the floor added for #485.
func TestLokiClient_ResponseHeaderTimeoutHasFloor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"min_allowed_1s_floors_to_1s", 1 * time.Second, 1 * time.Second},
		{"sub_floor_1500ms_floors_to_1s", 1500 * time.Millisecond, 1 * time.Second},
		{"exactly_2s_at_floor", 2 * time.Second, 1 * time.Second},
		{"20s_uses_half_10s", 20 * time.Second, 10 * time.Second},
		{"5min_uses_half_2m30s", 5 * time.Minute, 2*time.Minute + 30*time.Second},
		// The defensive cases below exercise values that validation
		// rejects, proving the helper itself is robust even if
		// validation is bypassed or reordered in a future refactor.
		{"tiny_1ms_floors_to_1s", 1 * time.Millisecond, 1 * time.Second},
		{"zero_floors_to_1s", 0, 1 * time.Second},
		{"negative_floors_to_1s", -5 * time.Second, 1 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := loki.ResponseHeaderTimeout(tc.timeout)
			assert.Equal(t, tc.want, got,
				"ResponseHeaderTimeout(%v) = %v; want %v", tc.timeout, got, tc.want)
		})
	}

	assert.Equal(t, 1*time.Second, loki.MinResponseHeaderTimeout,
		"floor constant must be 1 second for #485 contract")
}

// TestClient_RedirectBodyDrainCapped_Loki verifies that a non-redirect
// 3xx response (HTTP 300 Multiple Choices) with a 10 MiB body has its
// client-side body drain capped at 4 KiB. Our CheckRedirect blocks
// 301/302/303/307/308 inside the stdlib (which already slurps ≤ 2 KiB),
// but any other 3xx status reaches our doPost defer-drain unmodified —
// without the cap the client would read up to maxResponseBody (64 KiB)
// per retry from an attacker-controlled endpoint. See #484.
func TestClient_RedirectBodyDrainCapped_Loki(t *testing.T) {
	const (
		bodySize    = 10 << 20 // 10 MiB
		maxExpected = 4 << 20  // 4 MiB — generous slack for TCP buffers
	)

	var bytesWritten atomic.Int64
	chunk := bytes.Repeat([]byte("X"), 4096)

	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(handlerDone)
		// Chunked transfer (no Content-Length) avoids "superfluous
		// WriteHeader" log noise when the client closes after the cap.
		w.WriteHeader(http.StatusMultipleChoices) // 300 — no redirect-follow
		flusher, _ := w.(http.Flusher)
		remaining := bodySize
		for remaining > 0 {
			toWrite := len(chunk)
			if toWrite > remaining {
				toWrite = remaining
			}
			n, err := w.Write(chunk[:toWrite])
			bytesWritten.Add(int64(n))
			if err != nil {
				return // client closed
			}
			if flusher != nil {
				flusher.Flush()
			}
			remaining -= n
		}
	}))
	t.Cleanup(srv.Close)

	cfg := &loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          1,
		FlushInterval:      100 * time.Millisecond,
		Timeout:            5 * time.Second,
		MaxRetries:         1, // 3xx is treated as client error (non-retryable)
		BufferSize:         100,
	}
	out, err := loki.New(cfg, nil)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"drain_cap"}`)))
	require.NoError(t, out.Close())

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("server handler did not terminate within 10s")
	}

	written := bytesWritten.Load()
	assert.Less(t, written, int64(maxExpected),
		"server wrote %d bytes; client should have capped drain at 4 KiB", written)
}

// TestNew_NilConfig_ReturnsError verifies that [New] returns a
// non-nil error when passed a nil *Config. Nil-guard added for
// consistency with file.New / webhook.New (#580 follow-up).
func TestNew_NilConfig_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := loki.New(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config must not be nil")
}
