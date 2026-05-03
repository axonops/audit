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
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
)

// TestPushPayload_RoundTrip property-checks that the loki push
// payload round-trips: N events grouped under one stream serialise
// to a Loki push JSON document whose `values` array contains exactly
// N entries in input order, with monotonically non-decreasing
// timestamps.
//
// Per pre-coding test-analyst guidance: timestamps are bumped to
// enforce monotonic order (push.go:86-88), so the property asserts
// non-decreasing timestamps and per-stream order on the line
// payloads — NOT timestamp equality with input.
//
// The generator constrains all events to a single stream label set
// so cross-stream ordering (which is sorted by stream key, not input
// order) does not muddy the property.
func TestPushPayload_RoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		// Generate 2..20 events per the test-analyst guidance to keep
		// the property meaningful (single-event runs trivially pass).
		n := rapid.IntRange(2, 20).Draw(rt, "event_count")
		events := make([]loki.TestEvent, n)
		baseTime := time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)
		for i := 0; i < n; i++ {
			payload := rapid.SliceOfN(
				rapid.ByteRange(0x20, 0x7E),
				1, 64,
			).Draw(rt, "payload")
			events[i] = loki.TestEvent{
				Data: payload,
				Meta: audit.EventMetadata{
					EventType: "user_create", // single stream
					Severity:  3,
					Category:  "write",
					// Use the same timestamp for every event to force
					// the production code's timestamp-bumping path
					// (push.go:86-88) to fire — the bump only kicks in
					// when adjacent events share a timestamp.
					Timestamp: baseTime,
				},
			}
		}

		raw := loki.BuildTestPayload(t, loki.TestPayloadInput{
			Events:  events,
			AppName: "property-app",
			Host:    "property-host",
			PID:     12345,
		})

		assertLokiPushRoundTrip(rt, raw, events, n)
	})
}

// assertLokiPushRoundTrip decodes the Loki push payload and verifies
// the per-stream invariants: exactly one stream group, exactly n
// values, payloads round-trip in input order, and timestamps are
// monotonically non-decreasing (the production code bumps duplicate
// timestamps to enforce ordering — see push.go:86-88).
func assertLokiPushRoundTrip(rt *rapid.T, raw []byte, events []loki.TestEvent, n int) {
	var push lokiPushPayload
	require.NoError(rt, json.Unmarshal(raw, &push), "payload must be valid JSON")
	if len(push.Streams) != 1 {
		rt.Fatalf("expected exactly one stream, got %d (raw=%s)", len(push.Streams), raw)
	}
	stream := push.Streams[0]
	if len(stream.Values) != n {
		rt.Fatalf("expected %d values, got %d", n, len(stream.Values))
	}
	assertPerStreamPayloadOrder(rt, stream.Values, events)
	assertMonotonicTimestamps(rt, stream.Values)
}

// assertPerStreamPayloadOrder confirms that the i-th value's `line`
// field contains the i-th input payload as a substring (the JSON
// formatter wraps the payload bytes in additional structure).
func assertPerStreamPayloadOrder(rt *rapid.T, values [][]any, events []loki.TestEvent) {
	for i, val := range values {
		if len(val) < 2 {
			rt.Fatalf("value %d malformed: %v", i, val)
		}
		gotLine, ok := val[1].(string)
		if !ok {
			rt.Fatalf("value %d line is not a string: %v", i, val[1])
		}
		wantPayload := string(events[i].Data)
		if !strings.Contains(gotLine, wantPayload) {
			rt.Fatalf("value %d line missing input payload: got=%q, want substring=%q",
				i, gotLine, wantPayload)
		}
	}
}

// assertMonotonicTimestamps parses each value's timestamp string as
// an int64 UnixNano (a numeric comparison rather than a string sort
// is necessary because string < string would mis-order across digit-
// count boundaries) and confirms the sequence is non-decreasing.
func assertMonotonicTimestamps(rt *rapid.T, values [][]any) {
	var prev int64
	for i, val := range values {
		tsStr, ok := val[0].(string)
		if !ok {
			rt.Fatalf("value %d timestamp is not a string: %v", i, val[0])
		}
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			rt.Fatalf("value %d timestamp not parseable as int64: %s (%v)", i, tsStr, err)
		}
		if i > 0 && ts < prev {
			rt.Fatalf("timestamps not monotonic at value %d: prev=%d, this=%d", i, prev, ts)
		}
		prev = ts
	}
}

// lokiPushPayload mirrors the JSON shape buildPayload writes.
type lokiPushPayload struct {
	Streams []lokiPushStream `json:"streams"`
}

type lokiPushStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]any           `json:"values"`
}
