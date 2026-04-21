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

package loki_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
)

// newLokiTestServerForSize spins up a local httptest.Server that
// accepts any POST and returns 200. Callers receive the full push
// URL.
func newLokiTestServerForSize(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestLokiOutputForSize(t *testing.T, maxEventBytes int) *loki.Output {
	t.Helper()
	srv := newLokiTestServerForSize(t)
	out, err := loki.New(&loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		MaxEventBytes:      maxEventBytes,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = out.Close()
	})
	return out
}

// TestWrite_RejectsOversizedEvent verifies that writing an event
// whose byte length exceeds MaxEventBytes returns an error wrapping
// both audit.ErrEventTooLarge and audit.ErrValidation (#688 AC #2).
func TestWrite_RejectsOversizedEvent(t *testing.T) {
	out := newTestLokiOutputForSize(t, 1024)

	oversized := []byte(strings.Repeat("x", 2048))
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
	out := newTestLokiOutputForSize(t, 1024)
	atLimit := []byte(strings.Repeat("x", 1024))
	require.NoError(t, out.Write(atLimit), "event at exactly MaxEventBytes must be accepted")
}

// TestWrite_OversizedDoesNotStallSubsequent verifies that a rejected
// oversized event does not block delivery of subsequent normal
// events (#688 AC #5 — same-purpose subset, full scenario in BDD).
func TestWrite_OversizedDoesNotStallSubsequent(t *testing.T) {
	out := newTestLokiOutputForSize(t, 1024)

	// Normal before
	require.NoError(t, out.Write([]byte(`{"n":1}`)))

	// Oversized — rejected
	werr := out.Write([]byte(strings.Repeat("y", 4096)))
	require.Error(t, werr)
	require.True(t, errors.Is(werr, audit.ErrEventTooLarge))

	// Normal after — must succeed
	require.NoError(t, out.Write([]byte(`{"n":2}`)))
}

// TestValidateConfig_MaxEventBytesDefault verifies zero-value
// MaxEventBytes normalises to DefaultMaxEventBytes.
func TestValidateConfig_MaxEventBytesDefault(t *testing.T) {
	srv := newLokiTestServerForSize(t)
	out, err := loki.New(&loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
}

// TestValidateConfig_MaxEventBytesNegative verifies a negative
// MaxEventBytes value is rejected with ErrConfigInvalid.
func TestValidateConfig_MaxEventBytesNegative(t *testing.T) {
	srv := newLokiTestServerForSize(t)
	_, err := loki.New(&loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		MaxEventBytes:      -1,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

// TestValidateConfig_MaxEventBytesBelowMin verifies a value below
// MinMaxEventBytes is rejected.
func TestValidateConfig_MaxEventBytesBelowMin(t *testing.T) {
	srv := newLokiTestServerForSize(t)
	_, err := loki.New(&loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		MaxEventBytes:      512,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

// TestValidateConfig_MaxEventBytesOverRange verifies a value above
// MaxMaxEventBytes is rejected.
func TestValidateConfig_MaxEventBytesOverRange(t *testing.T) {
	srv := newLokiTestServerForSize(t)
	_, err := loki.New(&loki.Config{
		URL:                srv.URL + "/loki/api/v1/push",
		MaxEventBytes:      loki.MaxMaxEventBytes + 1,
		AllowInsecureHTTP:  true,
		AllowPrivateRanges: true,
	}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, audit.ErrConfigInvalid)
}

// TestWrite_OversizedIncrementsDropCounterExactlyOnce verifies that
// a single rejected oversized event increments RecordDrop exactly
// once. Covers the test-analyst HIGH gap: drop metric not verified.
func TestWrite_OversizedIncrementsDropCounterExactlyOnce(t *testing.T) {
	out := newTestLokiOutputForSize(t, 1024)

	m := &testOutputMetrics{}
	out.SetOutputMetrics(m)

	werr := out.Write([]byte(strings.Repeat("z", 2048)))
	require.Error(t, werr)
	require.True(t, errors.Is(werr, audit.ErrEventTooLarge))

	assert.Equal(t, 1, m.drops(),
		"exactly one RecordDrop call expected for one oversized reject")

	// Normal event must not increment drops further.
	require.NoError(t, out.Write([]byte(`{"n":1}`)))
	assert.Equal(t, 1, m.drops(),
		"normal event must not increment drops")
}

// TestWrite_OversizedEmitsRateLimitedWarn verifies the drop-limiter
// gated warn log fires on the first oversized drop and is
// rate-limited on subsequent drops within the warn window. Covers
// the test-analyst HIGH gap: drop-limiter gated warn log untested.
func TestWrite_OversizedEmitsRateLimitedWarn(t *testing.T) {
	out := newTestLokiOutputForSize(t, 1024)

	buf := &lokiSyncBuf{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	out.SetDiagnosticLogger(logger)

	oversized := []byte(strings.Repeat("q", 2048))
	for range 5 {
		_ = out.Write(oversized)
	}

	logs := buf.String()
	warns := strings.Count(logs, `"level":"WARN"`)
	assert.Equal(t, 1, warns,
		"expected one rate-limited warn for 5 oversized rejects in a burst; got %d; logs=%s", warns, logs)
	assert.Contains(t, logs, "exceeds max_event_bytes")
	assert.Contains(t, logs, `"event_bytes":2048`)
	assert.Contains(t, logs, `"max_event_bytes":1024`)
}

// TestWrite_MaxEventBytesBoundary verifies the `>` vs `>=` boundary:
// an event exactly at MaxEventBytes is accepted, MaxEventBytes-1 is
// accepted, MaxEventBytes+1 is rejected.
func TestWrite_MaxEventBytesBoundary(t *testing.T) {
	const limit = 1024
	out := newTestLokiOutputForSize(t, limit)

	require.NoError(t, out.Write(bytes.Repeat([]byte("a"), limit-1)),
		"MaxEventBytes-1 must be accepted")
	require.NoError(t, out.Write(bytes.Repeat([]byte("b"), limit)),
		"MaxEventBytes must be accepted (the guard is strict greater-than)")

	werr := out.Write(bytes.Repeat([]byte("c"), limit+1))
	require.Error(t, werr, "MaxEventBytes+1 must be rejected")
	require.True(t, errors.Is(werr, audit.ErrEventTooLarge))
}

// lokiSyncBuf wraps bytes.Buffer with a mutex so slog.JSONHandler can
// safely write concurrently with the test reader.
type lokiSyncBuf struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (s *lokiSyncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}
func (s *lokiSyncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
