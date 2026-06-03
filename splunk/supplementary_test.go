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

package splunk_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/splunk"
)

// Supplementary tests covering low-leverage paths identified by the
// test-analyst as residual coverage gaps. Targets recordBufferFull
// (0%), WithMaxIdleConns (0%), and the audit.Metrics non-nil
// branches of recordSuccess (60%) / recordDrop (75%).

// Note (#894): fakeCoreMetrics + TestOutput_RecordSuccess_CallsCoreMetricsRecordDelivery
// + TestOutput_RecordDrop_CallsCoreMetricsRecordDelivery removed when
// audit.Metrics.RecordDelivery / EventStatus were deleted. Per-event
// delivery counts now flow through OutputMetrics.RecordFlush (sum of
// batchSize) and OutputMetrics.RecordError (event count); the splunk
// recordSuccess / recordDrop paths are exercised end-to-end by the
// splunk_test.go RecordingMetrics-based tests.

// TestOutput_BufferFull_RecordsDropMetric covers recordBufferFull
// (0% before this test). Pattern: a slow server backs up flushes
// while writes continue at full speed; the BufferSize=100 channel
// fills and subsequent writes hit the `default` branch in Write.
func TestOutput_BufferFull_RecordsDropMetric(t *testing.T) {
	// /event handler sleeps long enough that the batch goroutine
	// blocks; /health returns immediately so construction succeeds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/services/collector/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"text":"HEC is healthy","code":17}`))
			return
		}
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	rec := &recordingMetrics{}
	cfg := validCfg(srv.URL)
	cfg.BufferSize = 100 // MinBufferSize
	cfg.BatchSize = 1    // every event triggers a flush; the flush blocks
	out, err := splunk.New(cfg, splunk.WithOutputMetrics(rec))
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Write enough events to overflow BufferSize while the batch
	// goroutine is blocked on the slow /event POST.
	for i := 0; i < 500; i++ {
		_ = out.Write([]byte(`{"event_type":"x"}`))
	}
	// The recordBufferFull path increments outputMetrics.RecordDrop.
	// We don't assert an exact count (it's race-dependent on when the
	// goroutine drains the first event before the buffer fills) — we
	// only assert that at least one buffer-full drop was recorded.
	assert.Eventually(t, func() bool {
		return rec.drops.Load() >= 1
	}, 1*time.Second, 10*time.Millisecond,
		"BufferSize=%d should not absorb 500 rapid writes against a 2s-blocked flush",
		cfg.BufferSize)
}

// TestWithMaxIdleConns covers the WithMaxIdleConns option (0% before
// this test). The option is honoured at transport construction; we
// verify the Output is constructed successfully with a non-default
// value and a sanity-bound zero value.
func TestWithMaxIdleConns(t *testing.T) {
	srv, _ := newStub(t)

	t.Run("explicit_value", func(t *testing.T) {
		out, err := splunk.New(validCfg(srv.URL), splunk.WithMaxIdleConns(50))
		require.NoError(t, err)
		require.NoError(t, out.Close())
	})

	t.Run("zero_value_falls_back_to_default", func(t *testing.T) {
		// 0 should be treated as "use default" by the option resolver
		// (the underlying http.Transport.MaxIdleConns defaults to 100
		// when zero is passed in; the splunk option resolver applies
		// its own default).
		out, err := splunk.New(validCfg(srv.URL), splunk.WithMaxIdleConns(0))
		require.NoError(t, err)
		require.NoError(t, out.Close())
	})
}
