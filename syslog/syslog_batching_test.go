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

// Unit tests for the batched writeLoop (#599). Kept in a dedicated
// file so the 3000-line syslog_test.go stays focused on connection /
// TLS / reconnect behaviour.

package syslog_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/syslog"
)

// countEventMarkers returns the number of `"n":` occurrences across
// every received chunk — one marker per event written. TCP may coalesce
// multiple framed messages into a single Read, so Read-count is not
// a reliable event count; substring matching is.
func countEventMarkers(msgs []string) int {
	total := 0
	for _, m := range msgs {
		total += strings.Count(m, `"n":`)
	}
	return total
}

// flushEvent records one observation of the writeLoop's testOnFlush
// hook (#705/#763): the flushed batch size and the trigger reason.
// fields ordered for fieldalignment govet check.
type flushEvent struct {
	reason string
	count  int
}

// installFlushHook attaches a buffered, non-blocking observer to the
// Output's flush hook and returns the receive channel. Buffer is sized
// well above any plausible flush count for the test; non-blocking
// send guards the production goroutine against test-side stalls (per
// the test-analyst pre-coding consult).
func installFlushHook(t *testing.T, out *syslog.Output) <-chan flushEvent {
	t.Helper()
	ch := make(chan flushEvent, 64)
	out.SetTestOnFlush(func(n int, reason string) {
		select {
		case ch <- flushEvent{count: n, reason: reason}:
		default:
		}
	})
	t.Cleanup(func() { out.SetTestOnFlush(nil) })
	return ch
}

// waitForFlush blocks until the hook signals or the deadline expires.
// Hard-stop after 5 s; on a healthy runner the wait is microseconds.
// If the deadline fires it indicates a real regression in the writeLoop,
// not test flake. (#705/#763 — replaces require.Eventually polling.)
func waitForFlush(t *testing.T, ch <-chan flushEvent) flushEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("testOnFlush hook never fired within 5 s — possible writeLoop regression")
		return flushEvent{}
	}
}

// TestWriteLoop_BatchesOnCountThreshold verifies that reaching
// BatchSize events triggers an immediate flush regardless of the
// (still-pending) FlushInterval timer (#599 AC #4a).
func TestWriteLoop_BatchesOnCountThreshold(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BatchSize:     10,
		FlushInterval: 10 * time.Second, // deliberately long — count threshold must fire first
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	flushes := installFlushHook(t, out)

	for i := 0; i < 10; i++ {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))))
	}

	ev := waitForFlush(t, flushes)
	assert.Equal(t, "count_threshold", ev.reason,
		"count threshold must trigger flush before FlushInterval elapses")
	assert.Equal(t, 10, ev.count, "flushed batch should contain all 10 events")
	// Use waitForMarkerCount (#763): the writeLoop's testOnFlush hook
	// fires before the server has finished reading every framed
	// message off the wire. Polling for the marker count avoids the
	// race that produced "9 not >= 10" failures under -race
	// -parallel=8.
	require.True(t, srv.waitForMarkerCount(10, 2*time.Second),
		"server should receive all 10 events after flush")
}

// TestWriteLoop_BatchesOnByteThreshold verifies that accumulated
// event bytes crossing MaxBatchBytes triggers a flush before the
// count threshold would (#599 AC #4b).
func TestWriteLoop_BatchesOnByteThreshold(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BatchSize:     1000, // deliberately high — byte threshold must fire first
		FlushInterval: 10 * time.Second,
		MaxBatchBytes: 4096, // 4 KiB
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	flushes := installFlushHook(t, out)

	// Each event is ~1 KiB; 5 events = 5 KiB, exceeding MaxBatchBytes.
	// Payload carries an `"n":` marker so the server-side polling
	// helper (waitForMarkerCount) can count delivered events
	// independently of TCP read coalescing.
	for i := 0; i < 5; i++ {
		event := []byte(fmt.Sprintf(`{"n":%d,"data":%q}`, i, strings.Repeat("a", 1000)))
		require.NoError(t, out.Write(event))
	}

	ev := waitForFlush(t, flushes)
	assert.Equal(t, "byte_threshold", ev.reason,
		"byte threshold must trigger flush before count or timer")
	assert.GreaterOrEqual(t, ev.count, 4,
		"flushed batch should contain at least 4 events when MaxBatchBytes hit")
	// Wait for the actual flushed batch size (ev.count) to reach
	// the server — same race as TestWriteLoop_BatchesOnCountThreshold
	// (#763). The hook fires before all bytes finish landing.
	require.True(t, srv.waitForMarkerCount(ev.count, 2*time.Second),
		"server should receive all flushed events")
}

// TestWriteLoop_FlushesOnTimerTimeout verifies that the
// FlushInterval timer triggers a flush of a partial batch (#599 AC #4c).
func TestWriteLoop_FlushesOnTimerTimeout(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BatchSize:     1000, // deliberately high so count threshold does not fire
		FlushInterval: 50 * time.Millisecond,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	flushes := installFlushHook(t, out)

	// Write a handful of events — well below BatchSize so only the
	// timer can cause delivery.
	for i := 0; i < 5; i++ {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))))
	}

	ev := waitForFlush(t, flushes)
	assert.Equal(t, "timer", ev.reason,
		"FlushInterval timer must trigger flush of partial batch")
	assert.Equal(t, 5, ev.count, "all 5 events should flush together on timer")
	// Poll for marker count rather than first-chunk arrival (#763).
	require.True(t, srv.waitForMarkerCount(5, 2*time.Second),
		"server should receive all 5 flushed events")
}

// TestWriteLoop_FlushesPartialOnClose verifies that Close drains
// pending events in the batch to the syslog server before returning
// (#599 AC #4d).
func TestWriteLoop_FlushesPartialOnClose(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BatchSize:     1000,
		FlushInterval: 10 * time.Second,
	})
	require.NoError(t, err)

	flushes := installFlushHook(t, out)

	for i := 0; i < 3; i++ {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))))
	}

	// Close must drain the pending batch before returning.
	require.NoError(t, out.Close())

	// The Close path drains via drainBatchNoRetry which fires the
	// hook with reason "close". Assert exactly that, plus the
	// expected event count, plus the server-side observation.
	ev := waitForFlush(t, flushes)
	assert.Equal(t, "close", ev.reason, "Close must trigger a final flush")
	assert.Equal(t, 3, ev.count, "Close must drain all 3 pending events")
	// Poll for marker count instead of a one-shot snapshot (#763) —
	// Close returns once the writer-side flush completes, but the
	// server's read loop may still be coalescing a multi-event chunk.
	require.True(t, srv.waitForMarkerCount(3, 2*time.Second),
		"Close must drain pending batch to syslog server")
}

// TestWriteLoop_OversizedEventFlushesAlone verifies that a single
// event exceeding MaxBatchBytes is flushed on its own rather than
// being dropped (#599 AC #5 via api-ergonomics-reviewer decision).
func TestWriteLoop_OversizedEventFlushesAlone(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		MaxBatchBytes: 1 << 10, // 1 KiB
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	flushes := installFlushHook(t, out)

	// Single event exceeding MaxBatchBytes.
	big := []byte(strings.Repeat("x", 4<<10)) // 4 KiB
	require.NoError(t, out.Write(big))

	ev := waitForFlush(t, flushes)
	assert.Equal(t, "byte_threshold", ev.reason,
		"oversized event must trigger immediate byte-threshold flush, not drop")
	assert.Equal(t, 1, ev.count, "oversized event flushes alone")
	require.True(t, srv.waitForData(2*time.Second))
}

// TestWriteLoop_BatchSizeOneDisablesBatching verifies the fast-path
// opt-out where BatchSize=1 effectively restores pre-#599 per-event
// flush semantics.
func TestWriteLoop_BatchSizeOneDisablesBatching(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BatchSize:     1,
		FlushInterval: 10 * time.Second, // irrelevant — every event hits count threshold
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	flushes := installFlushHook(t, out)

	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	ev := waitForFlush(t, flushes)
	assert.Equal(t, "count_threshold", ev.reason,
		"BatchSize=1 must flush every event immediately on count threshold")
	assert.Equal(t, 1, ev.count)
	require.True(t, srv.waitForData(2*time.Second))
}

// TestWriteLoop_MultipleFlushes verifies that the batch slice is
// correctly reused across flushes — no stale data, no panic.
func TestWriteLoop_MultipleFlushes(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BatchSize:     5,
		FlushInterval: 10 * time.Second,
	})
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	flushes := installFlushHook(t, out)

	// 3 batches of 5 events each — must trigger 3 count-threshold flushes.
	for batch := 0; batch < 3; batch++ {
		for i := 0; i < 5; i++ {
			require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"batch":%d,"n":%d}`, batch, i))))
		}
	}

	// Wait for exactly 3 count-threshold flushes; assert the
	// sequence rather than a polled count (test-analyst:
	// "exactly N flushes" needs sequence-aware assertions).
	for i := 0; i < 3; i++ {
		ev := waitForFlush(t, flushes)
		assert.Equal(t, "count_threshold", ev.reason,
			"flush %d/3 should be triggered by count threshold", i+1)
		assert.Equal(t, 5, ev.count,
			"flush %d/3 should contain exactly 5 events", i+1)
	}

	// Wait for every event to be observable on the server side.
	// The hook above proves the writeLoop flushed; this proves the
	// mock server's TCP read loop has consumed the bytes (the two
	// are independent goroutines and can race on quick test machines).
	expected := make([]string, 0, 15)
	for batch := 0; batch < 3; batch++ {
		for i := 0; i < 5; i++ {
			expected = append(expected, fmt.Sprintf(`"batch":%d,"n":%d`, batch, i))
		}
	}
	require.True(t, srv.waitForContent(expected, 2*time.Second),
		"all events should be observable in the mock server payload after the 3 count-threshold flushes")
}

// TestValidateSyslogConfig_BatchingDefaults verifies zero-value
// batching fields are normalised to defaults.
func TestValidateSyslogConfig_BatchingDefaults(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	// All zero — defaults apply.
	out, err := syslog.New(&syslog.Config{
		Network: "tcp",
		Address: srv.addr(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Defaults (100/5s/1 MiB) in effect: the Config was mutated
	// in place by validateSyslogBatchingConfig. Opaque from here;
	// the assertion is that New accepted the zero-value config and
	// did not return an error.
}

// TestValidateSyslogConfig_BatchingRejectsNegative verifies out-of-
// range batching fields return ErrConfigInvalid.
func TestValidateSyslogConfig_BatchingRejectsNegative(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	cases := []struct {
		name string
		cfg  syslog.Config
	}{
		{
			name: "negative BatchSize",
			cfg:  syslog.Config{Network: "tcp", Address: srv.addr(), BatchSize: -1},
		},
		{
			name: "BatchSize over max",
			cfg:  syslog.Config{Network: "tcp", Address: srv.addr(), BatchSize: syslog.MaxBatchSize + 1},
		},
		{
			name: "FlushInterval negative",
			cfg:  syslog.Config{Network: "tcp", Address: srv.addr(), FlushInterval: -1 * time.Second},
		},
		{
			name: "FlushInterval below min",
			cfg:  syslog.Config{Network: "tcp", Address: srv.addr(), FlushInterval: 500 * time.Microsecond},
		},
		{
			name: "FlushInterval over max",
			cfg:  syslog.Config{Network: "tcp", Address: srv.addr(), FlushInterval: 2 * time.Hour},
		},
		{
			name: "MaxBatchBytes negative",
			cfg:  syslog.Config{Network: "tcp", Address: srv.addr(), MaxBatchBytes: -1},
		},
		{
			name: "MaxBatchBytes below min",
			cfg:  syslog.Config{Network: "tcp", Address: srv.addr(), MaxBatchBytes: 512},
		},
		{
			name: "MaxBatchBytes over max",
			cfg:  syslog.Config{Network: "tcp", Address: srv.addr(), MaxBatchBytes: syslog.MaxMaxBatchBytes + 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := syslog.New(&tc.cfg)
			require.Error(t, err, "invalid config must be rejected")
			require.True(t, errors.Is(err, audit.ErrConfigInvalid),
				"error must wrap audit.ErrConfigInvalid; got %T: %v", err, err)
			if out != nil {
				_ = out.Close()
			}
		})
	}
}

// BenchmarkSyslogOutput_BatchedWrite measures the enqueue hot path
// with batching enabled (defaults 100/5s/1 MiB). Paired with the
// existing BenchmarkSyslogOutput_Write in bench-baseline.txt so
// benchstat can compare per-enqueue cost. Expected: enqueue-side
// cost is unchanged (channel send dominates); the throughput win
// from batching shows up on the drain side, not here.
func BenchmarkSyslogOutput_BatchedWrite(b *testing.B) {
	srv := newDiscardSyslogServer(b)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		BufferSize:    100_000,
		BatchSize:     100, // explicit; matches default post-#599
		FlushInterval: 5 * time.Second,
	}, syslog.WithDiagnosticLogger(silentBenchLogger()))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	event := []byte(`{"timestamp":"2026-04-14T12:00:00Z","event_type":"user_create","severity":5,"app_name":"bench","host":"localhost","outcome":"success","actor_id":"alice"}` + "\n")

	b.ReportAllocs()
	b.SetBytes(int64(len(event)))
	b.ResetTimer()
	for b.Loop() {
		_ = out.Write(event)
	}
}
