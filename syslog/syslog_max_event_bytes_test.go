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

// Tests for the Write-entry per-event size cap (#688 MaxEventBytes).

package syslog_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/syslog"
)

// TestWrite_RejectsOversizedEvent verifies that writing an event
// whose byte length exceeds MaxEventBytes returns an error wrapping
// both audit.ErrEventTooLarge and audit.ErrValidation, and does NOT
// enqueue the event (#688 AC #2 + #3).
func TestWrite_RejectsOversizedEvent(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: 1024, // 1 KiB
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	oversized := []byte(strings.Repeat("x", 2048)) // 2 KiB
	werr := out.Write(oversized)

	require.Error(t, werr)
	require.True(t, errors.Is(werr, audit.ErrEventTooLarge),
		"error must wrap audit.ErrEventTooLarge; got %T: %v", werr, werr)
	require.True(t, errors.Is(werr, audit.ErrValidation),
		"error must wrap audit.ErrValidation; got %T: %v", werr, werr)
}

// TestWrite_AcceptsAtLimit verifies that an event exactly at
// MaxEventBytes is accepted.
func TestWrite_AcceptsAtLimit(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: 1024,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	atLimit := []byte(strings.Repeat("x", 1024))
	require.NoError(t, out.Write(atLimit), "event at exactly MaxEventBytes must be accepted")
}

// TestWrite_OversizedDoesNotStallSubsequent verifies the core
// contract of #688: a rejected oversized event does not block
// delivery of subsequent normal events. Sends 3 events (normal,
// oversized, normal); asserts normal events reach the server and
// the oversized one is rejected with ErrEventTooLarge.
func TestWrite_OversizedDoesNotStallSubsequent(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: 1024,
		BatchSize:     1, // flush every event immediately
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// First normal event.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Oversized event — must be rejected, not enqueued.
	oversized := []byte(strings.Repeat("y", 4096))
	werr := out.Write(oversized)
	require.Error(t, werr)
	require.True(t, errors.Is(werr, audit.ErrEventTooLarge))

	// Second normal event — must still deliver despite prior reject.
	require.NoError(t, out.Write([]byte(`{"n":2}`)))

	// Both normal events should reach the server; oversized must not.
	require.Eventually(t, func() bool {
		msgs := strings.Join(srv.getMessages(), "\n")
		return strings.Contains(msgs, `"n":1`) && strings.Contains(msgs, `"n":2`)
	}, 2*time.Second, 10*time.Millisecond,
		"both normal events must reach the server after oversized reject")

	msgs := strings.Join(srv.getMessages(), "\n")
	assert.NotContains(t, msgs, "yyyyy",
		"rejected oversized event must not reach the server")
}

// TestValidateConfig_MaxEventBytesDefault verifies zero-value
// MaxEventBytes normalises to DefaultMaxEventBytes (#688 AC #1).
func TestValidateConfig_MaxEventBytesDefault(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	// All zero — defaults apply including MaxEventBytes.
	out, err := syslog.New(&syslog.Config{
		Network: "tcp",
		Address: srv.addr(),
	})
	require.NoError(t, err, "zero-value Config must accept default MaxEventBytes")
	t.Cleanup(func() { _ = out.Close() })
}

// TestValidateConfig_MaxEventBytesNegative verifies a negative
// MaxEventBytes value is rejected with ErrConfigInvalid.
func TestValidateConfig_MaxEventBytesNegative(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	_, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: -1,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

// TestValidateConfig_MaxEventBytesBelowMin verifies a value below
// MinMaxEventBytes is rejected with ErrConfigInvalid.
func TestValidateConfig_MaxEventBytesBelowMin(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	_, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: 512, // below 1 KiB minimum
	})
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

// TestValidateConfig_MaxEventBytesOverRange verifies a value above
// MaxMaxEventBytes is rejected with ErrConfigInvalid.
func TestValidateConfig_MaxEventBytesOverRange(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	_, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: syslog.MaxMaxEventBytes + 1,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

// TestWrite_OversizedIncrementsDropCounterExactlyOnce verifies that
// a single rejected oversized event increments RecordDrop exactly
// once — not zero (silent drop) and not twice (double-count via the
// buffer-full path). Covers the test-analyst HIGH gap: "drop metric
// not verified".
func TestWrite_OversizedIncrementsDropCounterExactlyOnce(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	om := &mockOutputMetrics{}
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: 1024,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithOutputMetrics(om))
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	// Single oversized event — must drop exactly once.
	werr := out.Write([]byte(strings.Repeat("z", 2048)))
	require.Error(t, werr)
	require.True(t, errors.Is(werr, audit.ErrEventTooLarge))

	assert.Equal(t, int64(1), om.drops.Load(),
		"exactly one RecordDrop call expected for one oversized reject")

	// Normal event must not increment drops further.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))
	assert.Equal(t, int64(1), om.drops.Load(),
		"normal event must not increment drops")
}

// TestWrite_OversizedEmitsRateLimitedWarn verifies the drop-limiter
// gated warn log fires on the first oversized drop and is
// rate-limited on subsequent drops within the warn window. Covers
// the test-analyst HIGH gap: "drop-limiter gated warn log entirely
// untested".
func TestWrite_OversizedEmitsRateLimitedWarn(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	buf := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: 1024,
		FlushInterval: 5 * time.Millisecond,
	}, syslog.WithDiagnosticLogger(logger))
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	oversized := []byte(strings.Repeat("q", 2048))
	for range 5 {
		_ = out.Write(oversized)
	}

	logs := buf.String()

	// Rate limiter should suppress repeated warns within the
	// dropWarnInterval window; exactly one warn is expected for
	// a burst sent in <1 ms.
	warns := strings.Count(logs, `"level":"WARN"`)
	assert.Equal(t, 1, warns,
		"expected one rate-limited warn for 5 oversized rejects in a burst; got %d; logs=%s", warns, logs)
	assert.Contains(t, logs, "exceeds max_event_bytes",
		"warn log must mention max_event_bytes threshold")
	assert.Contains(t, logs, `"event_bytes":2048`,
		"warn log must include event_bytes attribute")
	assert.Contains(t, logs, `"max_event_bytes":1024`,
		"warn log must include max_event_bytes attribute")
}

// TestWrite_MaxEventBytesBoundary verifies the `>` vs `>=` boundary:
// an event exactly at MaxEventBytes is accepted, MaxEventBytes-1 is
// accepted, MaxEventBytes+1 is rejected. Kills any mutation that
// inverts the comparator.
func TestWrite_MaxEventBytesBoundary(t *testing.T) {
	srv := newMockSyslogServer(t)
	defer srv.close()

	const limit = 1024
	out, err := syslog.New(&syslog.Config{
		Network:       "tcp",
		Address:       srv.addr(),
		MaxEventBytes: limit,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })

	require.NoError(t, out.Write(bytes.Repeat([]byte("a"), limit-1)),
		"MaxEventBytes-1 must be accepted")
	require.NoError(t, out.Write(bytes.Repeat([]byte("b"), limit)),
		"MaxEventBytes must be accepted (the guard is strict greater-than)")

	werr := out.Write(bytes.Repeat([]byte("c"), limit+1))
	require.Error(t, werr, "MaxEventBytes+1 must be rejected")
	require.True(t, errors.Is(werr, audit.ErrEventTooLarge))
}

// syncBuf wraps bytes.Buffer with a mutex so slog.JSONHandler can
// safely write concurrently with the test reader.
type syncBuf struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
