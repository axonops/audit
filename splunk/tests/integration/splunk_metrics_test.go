//go:build integration

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

// Integration tests for the splunk output's [audit.OutputMetrics]
// integration. Verifies the metric callbacks (RecordFlush, RecordDrop)
// fire with accurate counts under realistic delivery scenarios:
//
//   - Healthy path: flushSum == events submitted, drops == 0.
//   - Buffer overflow: drops scale linearly with submitted-after-full,
//     conservation invariant flushSum + drops == submitted holds.
//   - HEC code 24 capacity-warn: counts as a flush, NOT a drop —
//     the classification distinction matters for SLO dashboards.
//   - Oversize event: counts as a drop (different path from
//     buffer-full; same metric).
//
// Requires: make test-infra-splunk-up

package integration_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/splunk"
)

// recordingOutputMetrics is the test fixture implementing
// [audit.OutputMetrics]. Counts flushes (and the sum of batchSize
// across flushes — the "events delivered" total) plus drops with
// atomic counters so concurrent batch + drop goroutines can read
// and write without locking.
type recordingOutputMetrics struct {
	audit.NoOpOutputMetrics
	flushes  atomic.Int64
	flushSum atomic.Int64
	drops    atomic.Int64
}

func (r *recordingOutputMetrics) RecordFlush(batchSize int, _ time.Duration) {
	r.flushes.Add(1)
	r.flushSum.Add(int64(batchSize))
}

func (r *recordingOutputMetrics) RecordDrop() { r.drops.Add(1) }

// newMetricsAuditor builds an audit.Auditor wired to the given
// splunk output. Mirrors newCIMAuditor but takes the output as an
// argument so the test can pre-wire the OutputMetrics sink before
// New().
func newMetricsAuditor(t *testing.T, out *splunk.Output) *audit.Auditor {
	t.Helper()
	tax, err := audit.ParseTaxonomyYAML(cimTaxonomyYAML)
	require.NoError(t, err)
	a, err := audit.New(
		audit.WithTaxonomy(tax),
		audit.WithAppName("splunk-metrics-integration"),
		audit.WithHost("test-host"),
		audit.WithNamedOutput(out),
	)
	require.NoError(t, err)
	return a
}

// TestSplunkIntegration_OutputMetrics_FlushAccuracy_RealContainer —
// healthy-path conservation invariant: every submitted event ends
// up either flushed or dropped, with zero drops in the no-failure
// case. The flushSum (sum of batchSize across RecordFlush calls)
// MUST equal the submit count exactly.
func TestSplunkIntegration_OutputMetrics_FlushAccuracy_RealContainer(t *testing.T) {
	skipIfArm64(t)

	recorder := &recordingOutputMetrics{}
	out := newSplunkOutputWithMetrics(t, recorder, nil)
	auditor := newMetricsAuditor(t, out)

	m := marker(t)
	const n = 200
	for i := 0; i < n; i++ {
		require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
			"actor_id":    m,
			"target_id":   fmt.Sprintf("topic-%d", i),
			"target_type": "topic",
			"outcome":     "success",
		})))
	}
	require.NoError(t, auditor.Close())

	flushSum := recorder.flushSum.Load()
	drops := recorder.drops.Load()
	assert.Equal(t, int64(n), flushSum,
		"flushSum must equal submitted count exactly in the healthy path; flushSum=%d, drops=%d", flushSum, drops)
	assert.Zero(t, drops, "zero drops expected in the healthy path; got %d", drops)
	assert.Equal(t, int64(n), flushSum+drops,
		"conservation: every submitted event must be either flushed or dropped")
}

// TestSplunkIntegration_OutputMetrics_BufferFullDrops — exercise the
// buffer-full drop path deterministically by pointing the splunk
// output at a blocking httptest server. The first BatchSize events
// enter the channel and the batch goroutine sends them; the server
// blocks the response, holding the in-flight POST. Subsequent
// events queue up in the channel until it's full (BufferSize=100);
// then every further submit hits the non-blocking `default:` arm
// and increments drops.
//
// This test does NOT use the real Splunk container — the goal is
// metric semantics under controlled back-pressure, which requires
// a slow server we can pace.
func TestSplunkIntegration_OutputMetrics_BufferFullDrops(t *testing.T) {
	skipIfArm64(t)

	// Block all POSTs until the test releases. The 5000 capacity
	// keeps the test's request goroutine from deadlocking on send.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	t.Cleanup(srv.Close)

	recorder := &recordingOutputMetrics{}
	gz := false
	out, err := splunk.New(&splunk.Config{
		URL:                        srv.URL,
		Token:                      "fake",
		Sourcetype:                 "audit:event",
		Source:                     "audit",
		Index:                      "main",
		BatchSize:                  splunk.MinBufferSize, // 100
		MaxBatchBytes:              1 << 20,
		MaxEventBytes:              1 << 20,
		FlushInterval:              5 * time.Minute, // longest allowed; effectively "only flush on full-batch" for this test
		Timeout:                    5 * time.Second,
		BufferSize:                 splunk.MinBufferSize, // 100
		MaxRetries:                 0,
		Gzip:                       &gz,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: true,
		UserAgent:                  "test",
	}, nil, splunk.WithOutputMetrics(recorder))
	require.NoError(t, err)

	const submitted = 2000
	for i := 0; i < submitted; i++ {
		// Use raw output.Write (bypass auditor) to drive back-pressure
		// without an intermediate channel — auditor's own queue would
		// absorb drops before the splunk output sees them.
		_ = out.Write([]byte(fmt.Sprintf(
			`{"event_type":"user_create","actor_id":"alice","outcome":"success","seq":%d}`, i)))
	}

	// Release server so the buffered batch can flush, then close.
	close(release)
	require.NoError(t, out.Close())

	flushes := recorder.flushes.Load()
	flushSum := recorder.flushSum.Load()
	drops := recorder.drops.Load()
	t.Logf("metrics: flushes=%d flushSum=%d drops=%d submitted=%d",
		flushes, flushSum, drops, submitted)

	// Conservation: every submitted event ends as either flushed
	// or dropped — never lost.
	assert.Equal(t, int64(submitted), flushSum+drops,
		"conservation invariant: flushSum (%d) + drops (%d) MUST equal submitted (%d)",
		flushSum, drops, submitted)
	// Drops must be substantial — the test is meaningless if the
	// blocking server didn't actually induce back-pressure.
	assert.Greater(t, drops, int64(submitted/2),
		"drops should be substantial (>1000) with BufferSize=100, BatchSize=100, blocking server, 2000 submits")
}

// TestSplunkIntegration_OutputMetrics_HEC24NotCountedAsDrop — HEC
// code 24 (queues are at capacity) is a "soft warn": Splunk accepted
// the data but is asking the client to slow down. It MUST NOT count
// as a drop — operator SLO dashboards must distinguish "delivered
// with backpressure warning" from "lost on the floor".
func TestSplunkIntegration_OutputMetrics_HEC24NotCountedAsDrop(t *testing.T) {
	skipIfArm64(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// HEC 200 + code 24 is the documented capacity-warn shape.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"server is busy","code":24}`))
	}))
	t.Cleanup(srv.Close)

	recorder := &recordingOutputMetrics{}
	gz := false
	out, err := splunk.New(&splunk.Config{
		URL:                        srv.URL,
		Token:                      "fake",
		Sourcetype:                 "audit:event",
		Source:                     "audit",
		Index:                      "main",
		BatchSize:                  10,
		MaxBatchBytes:              1 << 20,
		MaxEventBytes:              1 << 20,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    2 * time.Second,
		BufferSize:                 100,
		MaxRetries:                 0,
		Gzip:                       &gz,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: true,
		UserAgent:                  "test",
	}, nil, splunk.WithOutputMetrics(recorder))
	require.NoError(t, err)

	const n = 10
	for i := 0; i < n; i++ {
		_ = out.Write([]byte(fmt.Sprintf(
			`{"event_type":"user_create","actor_id":"alice","outcome":"success","seq":%d}`, i)))
	}
	require.NoError(t, out.Close())

	flushSum := recorder.flushSum.Load()
	drops := recorder.drops.Load()
	assert.Equal(t, int64(n), flushSum,
		"HEC 200/code=24 must count toward flush total (capacity-warn = delivered with warning)")
	assert.Zero(t, drops,
		"HEC code 24 (capacity-warn) MUST NOT count as a drop — operators distinguish delivered-with-warn from lost")
}

// TestSplunkIntegration_OutputMetrics_OversizeDropped — a single
// event larger than MaxEventBytes MUST drop at Write time, count as
// exactly one drop, and never reach the network. This is the
// non-buffer-full drop path; the metric must still fire.
func TestSplunkIntegration_OutputMetrics_OversizeDropped(t *testing.T) {
	skipIfArm64(t)

	// Server should never be hit — the drop happens at Write.
	var serverHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		serverHits.Add(1)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	t.Cleanup(srv.Close)

	recorder := &recordingOutputMetrics{}
	gz := false
	out, err := splunk.New(&splunk.Config{
		URL:                        srv.URL,
		Token:                      "fake",
		Sourcetype:                 "audit:event",
		Source:                     "audit",
		Index:                      "main",
		BatchSize:                  10,
		MaxBatchBytes:              1 << 20,
		MaxEventBytes:              1024, // intentionally small
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    2 * time.Second,
		BufferSize:                 100,
		MaxRetries:                 0,
		Gzip:                       &gz,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: true,
		UserAgent:                  "test",
	}, nil, splunk.WithOutputMetrics(recorder))
	require.NoError(t, err)

	oversize := `{"event_type":"user_create","actor_id":"alice","outcome":"success","blob":"` +
		strings.Repeat("X", 2048) + `"}`
	err = out.Write([]byte(oversize))
	require.ErrorIs(t, err, audit.ErrEventTooLarge,
		"oversize Write must return ErrEventTooLarge synchronously")
	require.NoError(t, out.Close())

	assert.Equal(t, int64(1), recorder.drops.Load(),
		"oversize event drop must increment RecordDrop exactly once")
	assert.Zero(t, recorder.flushSum.Load(),
		"oversize event must never be flushed")
	assert.Zero(t, serverHits.Load(),
		"oversize event must never reach the network")
}

// newSplunkOutputWithMetrics is the metrics-test analogue of
// newSplunkOutput. Wires the given recorder into the splunk output
// via splunk.WithOutputMetrics before construction.
func newSplunkOutputWithMetrics(t *testing.T, recorder audit.OutputMetrics, mutate func(*splunk.Config)) *splunk.Output {
	t.Helper()
	gz := false
	cfg := &splunk.Config{
		URL:                        splunkURL,
		Token:                      splunkToken,
		Sourcetype:                 "audit:event",
		Source:                     "audit",
		Index:                      "main",
		BatchSize:                  10,
		MaxBatchBytes:              819200,
		MaxEventBytes:              1024 * 1024,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    10 * time.Second,
		BufferSize:                 1000,
		MaxRetries:                 5,
		Gzip:                       &gz,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: false,
	}
	if mutate != nil {
		mutate(cfg)
	}
	out, err := splunk.New(cfg, nil, splunk.WithOutputMetrics(recorder))
	require.NoError(t, err)
	return out
}
