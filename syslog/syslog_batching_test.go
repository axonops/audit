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
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	for i := 0; i < 10; i++ {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))))
	}

	require.Eventually(t, func() bool {
		return countEventMarkers(srv.getMessages()) >= 10
	}, 2*time.Second, 10*time.Millisecond,
		"count threshold must trigger flush before FlushInterval elapses")
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
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Each event is ~1 KiB; 5 events = 5 KiB, exceeding MaxBatchBytes.
	event := []byte(strings.Repeat("a", 1024))
	for i := 0; i < 5; i++ {
		require.NoError(t, out.Write(event))
	}

	require.Eventually(t, func() bool {
		return srv.messageCount() >= 4
	}, 2*time.Second, 10*time.Millisecond,
		"byte threshold must trigger flush before count or timer")
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
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Write a handful of events — well below BatchSize so only the
	// timer can cause delivery.
	for i := 0; i < 5; i++ {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))))
	}

	require.Eventually(t, func() bool {
		return countEventMarkers(srv.getMessages()) >= 5
	}, 2*time.Second, 10*time.Millisecond,
		"FlushInterval timer must trigger flush of partial batch")
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
	}, nil)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"n":%d}`, i))))
	}

	// Close must drain the pending batch before returning.
	require.NoError(t, out.Close())

	require.GreaterOrEqual(t, countEventMarkers(srv.getMessages()), 3,
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
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// Single event exceeding MaxBatchBytes.
	big := []byte(strings.Repeat("x", 4<<10)) // 4 KiB
	require.NoError(t, out.Write(big))

	require.Eventually(t, func() bool {
		return srv.messageCount() >= 1
	}, 2*time.Second, 10*time.Millisecond,
		"oversized event must trigger immediate flush, not drop")
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
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	require.Eventually(t, func() bool {
		return srv.messageCount() >= 1
	}, 1*time.Second, 5*time.Millisecond,
		"BatchSize=1 must flush every event immediately")
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
	}, nil)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()

	// 3 batches of 5 events each — must trigger 3 count-threshold flushes.
	for batch := 0; batch < 3; batch++ {
		for i := 0; i < 5; i++ {
			require.NoError(t, out.Write([]byte(fmt.Sprintf(`{"batch":%d,"n":%d}`, batch, i))))
		}
	}

	require.Eventually(t, func() bool {
		return countEventMarkers(srv.getMessages()) >= 15
	}, 2*time.Second, 10*time.Millisecond,
		"all three batches must flush in sequence")

	// Assert every event reached the server (no stale-slot retention).
	msgs := srv.getMessages()
	all := strings.Join(msgs, "\n")
	for batch := 0; batch < 3; batch++ {
		for i := 0; i < 5; i++ {
			assert.Contains(t, all, fmt.Sprintf(`"batch":%d,"n":%d`, batch, i),
				"event missing from delivered payload")
		}
	}
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
	}, nil)
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
			out, err := syslog.New(&tc.cfg, nil)
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
	}, nil, syslog.WithDiagnosticLogger(silentBenchLogger()))
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
