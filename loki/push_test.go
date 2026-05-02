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
	"compress/gzip"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/loki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushPayload mirrors the Loki push API JSON structure for test assertions.
type pushPayload struct {
	Streams []pushStream `json:"streams"`
}

type pushStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

// ---------------------------------------------------------------------------
// Stream grouping
// ---------------------------------------------------------------------------

func TestBuildPayload_PidZero_ExcludesPidLabel(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"test":"pid_zero"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		AppName: "app",
		Host:    "h1",
		PID:     0, // zero PID should exclude pid label
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
	require.Len(t, p.Streams, 1)
	_, hasPID := p.Streams[0].Stream["pid"]
	assert.False(t, hasPID, "pid=0 should exclude pid from stream labels")
}

func TestBuildPayload_UncategorisedEvent_ExcludesEventCategoryLabel(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"test":"uncategorised"}`), Meta: audit.EventMetadata{
				EventType: "health_check",
				Severity:  5,
				Category:  "", // uncategorised — no category
				Timestamp: ts,
			}},
		},
		AppName: "app",
		Host:    "h1",
		PID:     12345,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
	require.Len(t, p.Streams, 1)

	// event_category should NOT be in stream labels.
	_, hasCat := p.Streams[0].Stream["event_category"]
	assert.False(t, hasCat, "uncategorised event should not have event_category label")

	// Other labels should still be present.
	assert.Equal(t, "health_check", p.Streams[0].Stream["event_type"])
	assert.Equal(t, "5", p.Streams[0].Stream["severity"])
	assert.Equal(t, "app", p.Streams[0].Stream["app_name"])
	assert.Equal(t, "h1", p.Streams[0].Stream["host"])
}

func TestBuildPayload_MixedCategorisedAndUncategorised_SeparateStreams(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"actor":"alice","type":"categorised"}`), Meta: audit.EventMetadata{
				EventType: "user_create",
				Severity:  5,
				Category:  "write",
				Timestamp: ts,
			}},
			{Data: []byte(`{"actor":"alice","type":"uncategorised"}`), Meta: audit.EventMetadata{
				EventType: "health_check",
				Severity:  5,
				Category:  "", // uncategorised
				Timestamp: ts.Add(time.Millisecond),
			}},
		},
		AppName: "app",
		Host:    "h1",
		PID:     12345,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))

	// Two different streams — one with event_category, one without.
	assert.Len(t, p.Streams, 2, "categorised and uncategorised events should be in different streams")

	// Find which stream has event_category.
	var withCat, withoutCat *pushStream
	for i := range p.Streams {
		if _, ok := p.Streams[i].Stream["event_category"]; ok {
			withCat = &p.Streams[i]
		} else {
			withoutCat = &p.Streams[i]
		}
	}
	require.NotNil(t, withCat, "should have a stream with event_category")
	require.NotNil(t, withoutCat, "should have a stream without event_category")

	assert.Equal(t, "write", withCat.Stream["event_category"])
	assert.Equal(t, "user_create", withCat.Stream["event_type"])
	assert.Equal(t, "health_check", withoutCat.Stream["event_type"])
}

func TestBuildPayload_NoFrameworkFields(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"test":"no_fw"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		// No AppName, Host, PID — framework fields absent.
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
	require.Len(t, p.Streams, 1)
	_, hasAppName := p.Streams[0].Stream["app_name"]
	assert.False(t, hasAppName, "absent app_name should not produce a label")
	_, hasHost := p.Streams[0].Stream["host"]
	assert.False(t, hasHost, "absent host should not produce a label")
}

func TestBuildPayload_EscapeKeyValue_Backslash(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	// Two events with static labels that differ only by backslash vs pipe.
	// They must produce different streams to avoid data corruption.
	payloadA := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"v":"a"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		StaticLabels: map[string]string{"env": `a\b`},
		AppName:      "app",
		Host:         "h1",
		PID:          1,
	})
	payloadB := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"v":"b"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		StaticLabels: map[string]string{"env": "a|b"},
		AppName:      "app",
		Host:         "h1",
		PID:          1,
	})

	var pA, pB pushPayload
	require.NoError(t, json.Unmarshal(payloadA, &pA))
	require.NoError(t, json.Unmarshal(payloadB, &pB))
	require.Len(t, pA.Streams, 1)
	require.Len(t, pB.Streams, 1)
	assert.NotEqual(t, pA.Streams[0].Stream["env"], pB.Streams[0].Stream["env"],
		`static label values "a\\b" and "a|b" must produce different streams`)
}

// TestBuildPayload_NegativePID_IncludesLabel pins the SetFrameworkFields
// contract added in #494: pid==0 means "unset" (label excluded);
// pid!=0 (including negative values) is included verbatim. The
// pre-computed pidStr cache MUST handle negative pid the same way as
// positive — if a deployment passes a negative sentinel, the label
// surfaces in the wire payload.
func TestBuildPayload_NegativePID_IncludesLabel(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"v":"x"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		AppName: "app",
		Host:    "h1",
		PID:     -42,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
	require.Len(t, p.Streams, 1)
	assert.Equal(t, "-42", p.Streams[0].Stream["pid"],
		"negative pid value must surface as a string label, not be excluded")
}

// TestBuildPayload_StreamKeyDelimiterCollision proves that two events
// whose label values differ only by the position of the | / =
// delimiters (or by escaped vs literal occurrences) produce DISTINCT
// streams. The escapeKeyValue + m[string(b)] insert pattern in
// groupByStream must preserve this invariant — a regression here
// would silently merge streams in production. Companion to
// TestBuildPayload_EscapeKeyValue_Backslash.
func TestBuildPayload_StreamKeyDelimiterCollision(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)

	// Construct two events whose CONCATENATED label values would
	// produce identical bytes if escapeKeyValue were missing — but
	// the | / = delimiters land in different logical positions.
	// app_name="a|b" + host="c"  vs  app_name="a" + host="b|c"
	payloadA := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"v":"a"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		AppName: "a|b",
		Host:    "c",
		PID:     1,
	})
	payloadB := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"v":"b"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		AppName: "a",
		Host:    "b|c",
		PID:     1,
	})

	var pA, pB pushPayload
	require.NoError(t, json.Unmarshal(payloadA, &pA))
	require.NoError(t, json.Unmarshal(payloadB, &pB))
	require.Len(t, pA.Streams, 1)
	require.Len(t, pB.Streams, 1)
	assert.NotEqual(t, pA.Streams[0].Stream, pB.Streams[0].Stream,
		"label sets that share concatenated bytes but differ in delimiter placement must be distinct streams")
}

// ---------------------------------------------------------------------------
// Payload format
// ---------------------------------------------------------------------------

func TestBuildPayload_ValidJSON(t *testing.T) {
	t.Parallel()

	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{
				Data: []byte(`{"actor":"alice"}`),
				Meta: audit.EventMetadata{
					EventType: "user_login",
					Severity:  6,
					Category:  "auth",
					Timestamp: time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC),
				},
			},
		},
		AppName: "myapp",
		Host:    "prod-01",
		PID:     12345,
	})

	// Payload must be valid JSON.
	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p),
		"push payload must be valid JSON: %s", string(payload))
	require.Len(t, p.Streams, 1, "single event type should produce one stream")

	stream := p.Streams[0]
	assert.Equal(t, "user_login", stream.Stream["event_type"])
	assert.Equal(t, "6", stream.Stream["severity"])
	assert.Equal(t, "auth", stream.Stream["event_category"])
	assert.Equal(t, "myapp", stream.Stream["app_name"])
	assert.Equal(t, "prod-01", stream.Stream["host"])
	assert.Equal(t, "12345", stream.Stream["pid"])

	require.Len(t, stream.Values, 1)
	// Value[0] is the nanosecond timestamp string.
	assert.NotEmpty(t, stream.Values[0][0], "timestamp should be non-empty")
	// Value[1] is the JSON-escaped event line.
	assert.Contains(t, stream.Values[0][1], `"actor":"alice"`)
}

func TestBuildPayload_MultipleStreams(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"a":"1"}`), Meta: audit.EventMetadata{EventType: "type_a", Severity: 6, Timestamp: ts}},
			{Data: []byte(`{"b":"2"}`), Meta: audit.EventMetadata{EventType: "type_b", Severity: 4, Timestamp: ts}},
			{Data: []byte(`{"c":"3"}`), Meta: audit.EventMetadata{EventType: "type_a", Severity: 6, Timestamp: ts}},
		},
		AppName: "app",
		Host:    "h1",
		PID:     1,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
	assert.Len(t, p.Streams, 2, "two distinct event types should produce two streams")

	// Find each stream by event_type.
	streamsByType := make(map[string]pushStream)
	for _, s := range p.Streams {
		streamsByType[s.Stream["event_type"]] = s
	}

	typeA := streamsByType["type_a"]
	assert.Len(t, typeA.Values, 2, "type_a should have 2 events")

	typeB := streamsByType["type_b"]
	assert.Len(t, typeB.Values, 1, "type_b should have 1 event")
}

func TestBuildPayload_StaticLabels(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		StaticLabels: map[string]string{"environment": "prod", "job": "audit"},
		AppName:      "app",
		Host:         "h1",
		PID:          1,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
	require.Len(t, p.Streams, 1)
	assert.Equal(t, "prod", p.Streams[0].Stream["environment"])
	assert.Equal(t, "audit", p.Streams[0].Stream["job"])
}

func TestBuildPayload_ExcludedDynamicLabels(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Category: "cat", Timestamp: ts}},
		},
		ExcludeEventType: true,
		ExcludeSeverity:  true,
		AppName:          "app",
		Host:             "h1",
		PID:              1,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
	require.Len(t, p.Streams, 1)
	_, hasET := p.Streams[0].Stream["event_type"]
	assert.False(t, hasET, "event_type should be excluded")
	_, hasSev := p.Streams[0].Stream["severity"]
	assert.False(t, hasSev, "severity should be excluded")
	assert.Equal(t, "cat", p.Streams[0].Stream["event_category"],
		"non-excluded labels should still be present")
}

func TestBuildPayload_JSONEscaping(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{
				Data: []byte(`{"msg":"line with \"quotes\" and\nnewlines"}`),
				Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts},
			},
		},
		AppName: "app",
		Host:    "h1",
		PID:     1,
	})

	// The overall payload must be valid JSON even with special chars in the event.
	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p),
		"payload with special chars must be valid JSON: %s", string(payload))
}

func TestBuildPayload_MonotonicTimestamps(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"i":"1"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
			{Data: []byte(`{"i":"2"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
			{Data: []byte(`{"i":"3"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts}},
		},
		AppName: "app",
		Host:    "h1",
		PID:     1,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
	require.Len(t, p.Streams, 1)
	require.Len(t, p.Streams[0].Values, 3)

	// Timestamps must be strictly increasing within the same stream.
	for i := 1; i < len(p.Streams[0].Values); i++ {
		assert.Greater(t, p.Streams[0].Values[i][0], p.Streams[0].Values[i-1][0],
			"timestamps must be monotonically increasing within a stream")
	}
}

// ---------------------------------------------------------------------------
// Gzip compression
// ---------------------------------------------------------------------------

func TestMaybeCompress_Disabled(t *testing.T) {
	t.Parallel()

	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"test":"no_compress"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: time.Now()}},
		},
		AppName: "app",
		Host:    "h1",
		PID:     1,
	})

	// Uncompressed payload must be valid JSON.
	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p))
}

func TestCompressDecompress_RoundTrip(t *testing.T) {
	t.Parallel()

	compressed := loki.BuildTestCompressedPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"test":"roundtrip"}`), Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: time.Now()}},
		},
		Gzip:    true,
		AppName: "app",
		Host:    "h1",
		PID:     1,
	})

	// Decompress and verify valid JSON.
	r, err := gzip.NewReader(bytes.NewReader(compressed))
	require.NoError(t, err)
	decompressed, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	var p pushPayload
	require.NoError(t, json.Unmarshal(decompressed, &p),
		"decompressed payload must be valid JSON: %s", string(decompressed))
	require.Len(t, p.Streams, 1)
}

// ---------------------------------------------------------------------------
// Config validation — control chars in static labels
// ---------------------------------------------------------------------------

func TestBuildPayload_SpecialCharsInData(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	// Event data with special chars: quotes, backslashes, newlines,
	// Unicode (U+2028), HTML chars.
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{
				Data: []byte("{\"msg\":\"hello\\nworld\",\"path\":\"C:\\\\Users\",\"tag\":\"<b>&test</b>\",\"sep\":\"\xe2\x80\xa8\"}"),
				Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts},
			},
		},
		AppName: "app",
		Host:    "h1",
		PID:     1,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p),
		"payload with special chars must be valid JSON: %s", string(payload))
	require.Len(t, p.Streams, 1)
}

func TestBuildPayload_InvalidUTF8InData(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	// Invalid UTF-8 bytes (0xFF, 0xFE) and U+2029 paragraph separator.
	payload := loki.BuildTestPayload(t, loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{
				Data: []byte("{\"bad\":\"\xff\xfe\",\"para\":\"\xe2\x80\xa9\"}"),
				Meta: audit.EventMetadata{EventType: "test", Severity: 1, Timestamp: ts},
			},
		},
		AppName: "app",
		Host:    "h1",
		PID:     1,
	})

	var p pushPayload
	require.NoError(t, json.Unmarshal(payload, &p),
		"payload with invalid UTF-8 and U+2029 must be valid JSON: %s", string(payload))
	require.Len(t, p.Streams, 1)
}

func TestValidateConfig_StaticLabelControlChars(t *testing.T) {
	t.Parallel()

	cfg := &loki.Config{
		URL: "https://loki.example.com/loki/api/v1/push",
		Labels: loki.LabelConfig{
			Static: map[string]string{"env": "prod\ninjected"},
		},
	}
	err := loki.ValidateLokiConfig(cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrConfigInvalid)
	assert.Contains(t, err.Error(), "control characters")
}

func TestMaybeCompress_GzipError_ReturnsError(t *testing.T) {
	t.Parallel()

	input := loki.TestPayloadInput{
		Events: []loki.TestEvent{
			{Data: []byte(`{"event_type":"test"}`), Meta: audit.EventMetadata{Severity: 5}},
		},
		StaticLabels: map[string]string{"env": "test"},
		AppName:      "test",
		Host:         "localhost",
		Gzip:         true,
	}
	o := loki.PreparePayloadForTest(t, input)
	defer func() { _ = o.Close() }()

	// Verify compression works normally first.
	body, compressed, err := o.MaybeCompressForTest()
	require.NoError(t, err)
	assert.True(t, compressed, "normal compression should succeed")
	assert.NotEmpty(t, body)

	// Now inject the failing writer and rebuild payload.
	o.ForceCompressError()
	o.RebuildPayloadForTest(t, input)

	_, _, err = o.MaybeCompressForTest()
	require.Error(t, err, "maybeCompress should return error with failing writer")
	// text-only: push.go:313 returns raw fmt.Errorf without a sentinel wrap.
	assert.Contains(t, err.Error(), "gzip write")
}
