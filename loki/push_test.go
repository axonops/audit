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

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/loki"
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

func TestOutput_StreamGrouping_SingleStream(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.BatchSize = 10
	cfg.FlushInterval = 10 * time.Second

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)
	out.SetFrameworkFields("myapp", "prod-01", 12345)

	// Write events with identical metadata — should produce one stream.
	meta := audit.EventMetadata{
		EventType: "user_login",
		Severity:  6,
		Category:  "auth",
		Timestamp: time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC),
	}

	for i := 0; i < 3; i++ {
		require.NoError(t, out.WriteWithMetadata([]byte(`{"actor":"alice"}`), meta))
	}

	require.NoError(t, out.Close())
}

func TestOutput_StreamGrouping_MultipleStreams(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.BatchSize = 10
	cfg.FlushInterval = 10 * time.Second

	out, err := loki.New(cfg, nil, nil)
	require.NoError(t, err)
	out.SetFrameworkFields("myapp", "prod-01", 1)

	ts := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)

	// Write events with different event types — should produce multiple streams.
	require.NoError(t, out.WriteWithMetadata(
		[]byte(`{"action":"login"}`),
		audit.EventMetadata{EventType: "user_login", Severity: 6, Category: "auth", Timestamp: ts},
	))
	require.NoError(t, out.WriteWithMetadata(
		[]byte(`{"action":"logout"}`),
		audit.EventMetadata{EventType: "user_logout", Severity: 6, Category: "auth", Timestamp: ts},
	))
	require.NoError(t, out.WriteWithMetadata(
		[]byte(`{"action":"create"}`),
		audit.EventMetadata{EventType: "resource_create", Severity: 4, Category: "data", Timestamp: ts},
	))

	require.NoError(t, out.Close())
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
		Compress: true,
		AppName:  "app",
		Host:     "h1",
		PID:      1,
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
	// Unicode (U+2028, U+2029), invalid UTF-8, and HTML chars.
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
