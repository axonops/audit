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

// Integration tests for the ACK state machine against a real Splunk
// Enterprise container with indexer acknowledgement enabled on the
// HEC token. The library-side state machine is exhaustively
// unit-tested in splunk/ack_test.go; these tests verify the
// end-to-end behaviour against Splunk's real /services/collector/ack
// endpoint.
//
// Requires: make test-infra-splunk-up
//
// The test container's HEC token MUST have indexer acknowledgement
// enabled (set in tests/bdd/docker-compose.splunk.yml's
// SPLUNK_HEC_ACKNOWLEDGEMENTS environment variable). If ACK is
// disabled on the test token, the construction-time feature-detect
// probe returns ErrAckDisabled and these tests are skipped via the
// skipIfAckDisabled helper.

package integration_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit/splunk"
)

// skipIfAckDisabled attempts construction against the configured
// AckMode. If the test container's token doesn't have ACK enabled,
// the feature-detect probe returns ErrAckDisabled — the test
// skips cleanly so CI doesn't fail on infrastructure setup.
func skipIfAckDisabled(t *testing.T, mode splunk.AckMode) {
	t.Helper()
	cfg := &splunk.Config{
		URL:                        splunkURL,
		Token:                      splunkToken,
		Sourcetype:                 "audit:event",
		Index:                      "main",
		BatchSize:                  10,
		MaxBatchBytes:              819200,
		MaxEventBytes:              1024 * 1024,
		FlushInterval:              200 * time.Millisecond,
		Timeout:                    10 * time.Second,
		BufferSize:                 100,
		MaxRetries:                 1,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: false,
		AckMode:                    mode,
		AckPollInterval:            500 * time.Millisecond,
		AckResendWindow:            30 * time.Second,
	}
	out, err := splunk.New(cfg, nil)
	if errors.Is(err, splunk.ErrAckDisabled) {
		t.Skipf("test container's HEC token does not have ACK enabled: %v", err)
	}
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// newSplunkOutputWithACK is the ACK-test analogue of newSplunkOutput.
func newSplunkOutputWithACK(t *testing.T, mode splunk.AckMode, mutate func(*splunk.Config)) *splunk.Output {
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
		BufferSize:                 100,
		MaxRetries:                 1,
		Gzip:                       &gz,
		AllowInsecureHTTP:          true,
		AllowPrivateRanges:         true,
		DisableStartupVerification: false,
		AckMode:                    mode,
		AckPollInterval:            500 * time.Millisecond,
		AckResendWindow:            30 * time.Second,
	}
	if mutate != nil {
		mutate(cfg)
	}
	out, err := splunk.New(cfg, nil)
	require.NoError(t, err)
	return out
}

// TestSplunkIntegration_AckRequired_PositiveAck — AckModeRequired
// against a real Splunk container. After Write+Close, every event
// should have received a positive ack and the snapshot's Pending
// counter should be zero.
func TestSplunkIntegration_AckRequired_PositiveAck(t *testing.T) {
	skipIfArm64(t)
	skipIfAckDisabled(t, splunk.AckModeRequired)
	out := newSplunkOutputWithACK(t, splunk.AckModeRequired, nil)

	m := marker(t)
	const n = 5
	for i := 0; i < n; i++ {
		event := []byte(fmt.Sprintf(
			`{"timestamp":"%s","event_type":"user_create","actor_id":%q,"outcome":"success","seq":%d}`,
			time.Now().UTC().Format(time.RFC3339Nano), m, i))
		require.NoError(t, out.Write(event))
	}

	// Close drains the in-flight buffer up to 2*Timeout. All events
	// should be confirmed by then.
	require.NoError(t, out.Close())

	snap := out.AckMetricsSnapshot()
	assert.Equal(t, 0, snap.Pending,
		"all events should be confirmed before Close returns; pending=%d", snap.Pending)
	assert.GreaterOrEqual(t, snap.Confirmed, int64(n),
		"confirmed count should equal sent count; confirmed=%d, sent=%d", snap.Confirmed, n)

	// Verify the events landed in Splunk searchable form.
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="audit:event" actor_id=%q`, m), n)
	require.GreaterOrEqual(t, len(hits), n,
		"all %d events should be searchable in Splunk after ack confirmation", n)
}

// TestSplunkIntegration_AckRequired_ResendOnTimeout — pin behaviour
// of the resend-on-timeout path against a real Splunk. The test
// uses a very short AckResendWindow so the first attempt's ack is
// almost guaranteed to be slower than the window, triggering a
// resend that lands as a duplicate. The post-search must find at
// least N events; duplicates are an accepted side-effect of the
// resend policy.
func TestSplunkIntegration_AckRequired_ResendOnTimeout(t *testing.T) {
	skipIfArm64(t)
	skipIfAckDisabled(t, splunk.AckModeRequired)
	out := newSplunkOutputWithACK(t, splunk.AckModeRequired, func(c *splunk.Config) {
		c.AckPollInterval = 100 * time.Millisecond
		c.AckResendWindow = 200 * time.Millisecond // aggressive — likely to time out
	})

	m := marker(t)
	event := []byte(fmt.Sprintf(
		`{"timestamp":"%s","event_type":"user_create","actor_id":%q,"outcome":"success"}`,
		time.Now().UTC().Format(time.RFC3339Nano), m))
	require.NoError(t, out.Write(event))

	// Give the resend timer a chance to fire if Splunk doesn't ack
	// within the window. The Close drain waits up to 2*Timeout.
	require.NoError(t, out.Close())

	// At least 1 event should be searchable. The TimedOut counter
	// may or may not be non-zero depending on Splunk's ack latency
	// — both outcomes are valid (Splunk acked fast → 0 timeouts;
	// Splunk acked slow → 1+ timeout, 2+ events on disk).
	hits := waitForEvent(t, fmt.Sprintf(`index=main sourcetype="audit:event" actor_id=%q`, m), 1)
	require.GreaterOrEqual(t, len(hits), 1,
		"resend-eligible event must reach Splunk's index")

	snap := out.AckMetricsSnapshot()
	// Confirmed + TimedOut should account for at least 1 batch.
	// (If both are 0 something is very wrong.)
	totalAccounted := snap.Confirmed + snap.TimedOut
	assert.GreaterOrEqual(t, totalAccounted, int64(1),
		"either Confirmed or TimedOut must record the in-flight batch")
}

// TestSplunkIntegration_AckBestEffort_MetricsExposed — verify
// AckModeBestEffort produces metric updates (confirmed > 0) against
// a real Splunk without gating the producer.
func TestSplunkIntegration_AckBestEffort_MetricsExposed(t *testing.T) {
	skipIfArm64(t)
	skipIfAckDisabled(t, splunk.AckModeBestEffort)
	out := newSplunkOutputWithACK(t, splunk.AckModeBestEffort, nil)

	m := marker(t)
	const n = 3
	for i := 0; i < n; i++ {
		event := []byte(fmt.Sprintf(
			`{"timestamp":"%s","event_type":"user_create","actor_id":%q,"outcome":"success","seq":%d}`,
			time.Now().UTC().Format(time.RFC3339Nano), m, i))
		require.NoError(t, out.Write(event))
	}
	require.NoError(t, out.Close())

	snap := out.AckMetricsSnapshot()
	assert.GreaterOrEqual(t, snap.Confirmed, int64(1),
		"best-effort mode must record at least 1 confirmed ack; confirmed=%d", snap.Confirmed)
	assert.Zero(t, snap.BufferFullDrops,
		"best-effort mode never gates the buffer; buffer-full drops must be 0")
}
