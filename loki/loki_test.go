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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/loki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// lokiTestServer creates an httptest.Server that returns 204 on every
// request. The server URL is returned for use in Config.URL.
func lokiTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// validConfig returns a minimal Config suitable for testing, pointing
// at the provided test server URL.
func validConfig() *loki.Config {
	return validConfigWithURL("http://localhost:3100/loki/api/v1/push")
}

// validConfigWithURL returns a Config pointing at the given URL.
func validConfigWithURL(url string) *loki.Config {
	return &loki.Config{
		URL:                url,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
		BatchSize:          100,
		FlushInterval:      1 * time.Second,
		Timeout:            5 * time.Second,
		MaxRetries:         1,
		BufferSize:         1000,
		Compress:           true,
	}
}

// ---------------------------------------------------------------------------
// New() — constructor tests
// ---------------------------------------------------------------------------

func TestNew_ValidConfig(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NoError(t, out.Close())
}

func TestNew_InvalidConfig(t *testing.T) {
	t.Parallel()

	cfg := &loki.Config{} // empty URL
	_, err := loki.New(cfg, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
}

func TestNew_ConfigCopied(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	originalURL := cfg.URL
	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	// Mutating the original config must not affect the output.
	cfg.URL = "http://mutated:9999/bad"
	assert.Equal(t, "loki:localhost:3100", out.Name(),
		"Output name should use the original URL, not the mutated one")
	_ = originalURL
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Name() and DestinationKey()
// ---------------------------------------------------------------------------

func TestOutput_Name(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "loki:localhost:3100", out.Name())
	require.NoError(t, out.Close())
}

func TestOutput_DestinationKey(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.URL = "http://loki.example.com:3100/loki/api/v1/push?token=secret#frag"
	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "http://loki.example.com:3100/loki/api/v1/push",
		out.DestinationKey(),
		"DestinationKey must strip query params and fragment")
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// ReportsDelivery()
// ---------------------------------------------------------------------------

func TestOutput_ReportsDelivery(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)
	assert.True(t, out.ReportsDelivery(),
		"Loki output must report its own delivery metrics")
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Interface assertions
// ---------------------------------------------------------------------------

func TestOutput_ImplementsInterfaces(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, out.Close()) }()

	// These are compile-time checks too (var _ blocks in loki.go),
	// but runtime verification confirms the factory returns the right type.
	assert.Implements(t, (*audit.Output)(nil), out)
	assert.Implements(t, (*audit.MetadataWriter)(nil), out)
	assert.Implements(t, (*audit.DeliveryReporter)(nil), out)
	assert.Implements(t, (*audit.DestinationKeyer)(nil), out)
	assert.Implements(t, (*audit.FrameworkFieldReceiver)(nil), out)
}

// ---------------------------------------------------------------------------
// SetFrameworkFields()
// ---------------------------------------------------------------------------

func TestOutput_SetFrameworkFields(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)

	// SetFrameworkFields should not panic with any values.
	out.SetFrameworkFields("myapp", "prod-01", "UTC", 12345)
	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Write() and WriteWithMetadata()
// ---------------------------------------------------------------------------

func TestOutput_Write(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)

	err = out.Write([]byte(`{"event":"test"}`))
	assert.NoError(t, err, "Write should succeed on a valid output")
	require.NoError(t, out.Close())
}

func TestOutput_WriteWithMetadata(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)

	meta := audit.EventMetadata{
		EventType: "user_login",
		Severity:  6,
		Category:  "authentication",
		Timestamp: time.Now(),
	}
	err = out.WriteWithMetadata([]byte(`{"actor_id":"alice"}`), meta)
	assert.NoError(t, err, "WriteWithMetadata should succeed on a valid output")
	require.NoError(t, out.Close())
}

func TestOutput_WriteAfterClose(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	err = out.Write([]byte(`{"event":"test"}`))
	assert.ErrorIs(t, err, audit.ErrOutputClosed,
		"Write after Close must return ErrOutputClosed")

	err = out.WriteWithMetadata([]byte(`{"event":"test"}`), audit.EventMetadata{})
	assert.ErrorIs(t, err, audit.ErrOutputClosed,
		"WriteWithMetadata after Close must return ErrOutputClosed")
}

func TestOutput_ConcurrentWriteAndClose(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	cfg := validConfigWithURL(srv.URL)
	cfg.BufferSize = 10000

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)

	// Launch 50 goroutines writing concurrently.
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = out.Write([]byte(`{"event":"concurrent"}`))
			}
		}()
	}

	// Close while writers are still running.
	require.NoError(t, out.Close())

	// Wait for all writers to finish.
	wg.Wait()

	// Post-close writes must return ErrOutputClosed (no panic).
	err = out.Write([]byte(`{"event":"after_close"}`))
	assert.ErrorIs(t, err, audit.ErrOutputClosed)
}

// ---------------------------------------------------------------------------
// Close() — idempotent
// ---------------------------------------------------------------------------

func TestOutput_CloseIdempotent(t *testing.T) {
	t.Parallel()

	out, err := loki.New(validConfig(), nil, nil)
	require.NoError(t, err)

	require.NoError(t, out.Close(), "first Close")
	require.NoError(t, out.Close(), "second Close must be idempotent")
	require.NoError(t, out.Close(), "third Close must be idempotent")
}

// ---------------------------------------------------------------------------
// Buffer full — drop behaviour
// ---------------------------------------------------------------------------

func TestOutput_BufferFull_DropsEvent(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BufferSize = loki.MinBufferSize  // smallest allowed buffer (100)
	cfg.BatchSize = loki.MaxBatchSize    // prevent size-based flush
	cfg.FlushInterval = 10 * time.Second // prevent timer-based flush

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	// Write from multiple goroutines to overwhelm the buffer faster
	// than the batch goroutine can drain it.
	data := []byte(`{"event":"fill"}`)
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = out.Write(data)
			}
		}()
	}
	wg.Wait()

	require.True(t, metrics.waitForDrops(1, 2*time.Second),
		"at least some events should be dropped when buffer is full")

	require.NoError(t, out.Close())
}

// ---------------------------------------------------------------------------
// Flush metrics — batch goroutine records flushes
// ---------------------------------------------------------------------------

func TestOutput_FlushOnClose(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.FlushInterval = 10 * time.Second // prevent timer flush

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	// Write a few events, then close.
	for i := 0; i < 5; i++ {
		require.NoError(t, out.Write([]byte(`{"event":"flush_test"}`)))
	}

	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 0,
		"Close must flush remaining events")
}

func TestOutput_FlushOnBatchSize(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BatchSize = 5
	cfg.FlushInterval = 10 * time.Second // prevent timer flush

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	// Write exactly BatchSize events to trigger a flush.
	for i := 0; i < cfg.BatchSize; i++ {
		require.NoError(t, out.Write([]byte(`{"event":"batch_size_test"}`)))
	}

	require.True(t, metrics.waitForFlush(1, 2*time.Second),
		"batch goroutine must flush when BatchSize is reached")

	require.NoError(t, out.Close())
}

func TestOutput_FlushOnTimer(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BatchSize = 10000                      // large, prevent size-based flush
	cfg.FlushInterval = 200 * time.Millisecond // short timer

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	require.NoError(t, out.Write([]byte(`{"event":"timer_test"}`)))

	require.True(t, metrics.waitForFlush(1, 2*time.Second),
		"batch goroutine must flush when FlushInterval elapses")

	require.NoError(t, out.Close())
}

func TestOutput_FlushOnMaxBatchBytes(t *testing.T) {
	t.Parallel()

	srv := lokiTestServer(t)
	metrics := &testLokiMetrics{}
	cfg := validConfigWithURL(srv.URL)
	cfg.BatchSize = 10000                     // large, prevent count-based flush
	cfg.MaxBatchBytes = loki.MinMaxBatchBytes // smallest allowed byte threshold (1024)
	cfg.FlushInterval = 10 * time.Second      // prevent timer flush

	out, err := loki.New(cfg, nil, metrics)
	require.NoError(t, err)

	// Each event is ~22 bytes; 1024 / 22 ≈ 46 events to trigger.
	// Write enough to trigger at least one mid-batch flush.
	for i := 0; i < 100; i++ {
		require.NoError(t, out.Write([]byte(`{"event":"bytes_test"}`)))
	}

	require.True(t, metrics.waitForFlush(1, 2*time.Second),
		"MaxBatchBytes threshold should trigger a flush")

	require.NoError(t, out.Close())

	assert.Greater(t, metrics.flushCount(), 1,
		"MaxBatchBytes should trigger flush before final Close flush")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type testLokiMetrics struct {
	mu        sync.Mutex
	dropCount int
	flushN    int
}

func (m *testLokiMetrics) RecordLokiDrop() {
	m.mu.Lock()
	m.dropCount++
	m.mu.Unlock()
}

func (m *testLokiMetrics) RecordLokiFlush(_ int, _ time.Duration) {
	m.mu.Lock()
	m.flushN++
	m.mu.Unlock()
}

func (m *testLokiMetrics) RecordLokiRetry(_, _ int) {}
func (m *testLokiMetrics) RecordLokiError(_ int)    {}

func (m *testLokiMetrics) drops() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropCount
}

func (m *testLokiMetrics) flushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushN
}

func (m *testLokiMetrics) waitForFlush(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if m.flushCount() >= n {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (m *testLokiMetrics) waitForDrops(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		if m.drops() >= n {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(5 * time.Millisecond):
		}
	}
}
