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

package audit_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/axonops/go-audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testTime = time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

var testDef = &audit.EventDef{
	Category: "write",
	Required: []string{"outcome", "actor_id", "subject"},
	Optional: []string{"schema_type", "version"},
}

// ---------------------------------------------------------------------------
// JSONFormatter tests
// ---------------------------------------------------------------------------

func TestJSONFormatter_ValidOutput(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}, testDef)
	require.NoError(t, err)

	// Must end with newline.
	assert.True(t, data[len(data)-1] == '\n', "output must end with newline")

	// Must be valid JSON.
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	assert.Equal(t, "schema_register", m["event_type"])
	assert.Equal(t, "success", m["outcome"])
	assert.Equal(t, "alice", m["actor_id"])
	assert.NotEmpty(t, m["timestamp"])
}

func TestJSONFormatter_FieldOrdering(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"schema_type": "AVRO",
		"version":     1,
	}, testDef)
	require.NoError(t, err)

	raw := string(data)
	// Framework fields first.
	tsIdx := strings.Index(raw, `"timestamp"`)
	etIdx := strings.Index(raw, `"event_type"`)
	// Required fields sorted: actor_id, outcome, subject.
	aiIdx := strings.Index(raw, `"actor_id"`)
	oIdx := strings.Index(raw, `"outcome"`)
	sIdx := strings.Index(raw, `"subject"`)
	// Optional fields sorted: schema_type, version.
	stIdx := strings.Index(raw, `"schema_type"`)
	vIdx := strings.Index(raw, `"version"`)

	assert.Less(t, tsIdx, etIdx, "timestamp before event_type")
	assert.Less(t, etIdx, aiIdx, "event_type before required fields")
	assert.Less(t, aiIdx, oIdx, "actor_id before outcome (sorted)")
	assert.Less(t, oIdx, sIdx, "outcome before subject (sorted)")
	assert.Less(t, sIdx, stIdx, "required before optional")
	assert.Less(t, stIdx, vIdx, "schema_type before version (sorted)")
}

func TestJSONFormatter_DurationMarshalling(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"subject":     "my-topic",
		"duration_ms": 1500 * time.Millisecond,
	}, testDef)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	// duration_ms should be int64 milliseconds, not Go duration string.
	assert.Equal(t, float64(1500), m["duration_ms"])
}

func TestJSONFormatter_TimestampRFC3339Nano(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampRFC3339Nano}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	ts, ok := m["timestamp"].(string)
	require.True(t, ok, "timestamp should be a string for RFC3339Nano")
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	require.NoError(t, err)
	assert.Equal(t, testTime, parsed)
}

func TestJSONFormatter_TimestampUnixMillis(t *testing.T) {
	f := &audit.JSONFormatter{Timestamp: audit.TimestampUnixMillis}
	data, err := f.Format(testTime, "ev", audit.Fields{"outcome": "ok"}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	ts, ok := m["timestamp"].(float64)
	require.True(t, ok, "timestamp should be a number for unix_ms")
	assert.Equal(t, float64(testTime.UnixMilli()), ts)
}

func TestJSONFormatter_OmitEmptyTrue(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: true}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
		// schema_type and version not provided
	}, testDef)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	_, has := m["schema_type"]
	assert.False(t, has, "OmitEmpty should omit missing optional fields")
}

func TestJSONFormatter_OmitEmptyFalse(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: false}
	data, err := f.Format(testTime, "schema_register", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
		"subject":  "my-topic",
	}, testDef)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	_, has := m["schema_type"]
	assert.True(t, has, "OmitEmpty=false should include all registered fields")
	assert.Nil(t, m["schema_type"], "missing optional should be null")
}

func TestJSONFormatter_UnicodeValues(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "success",
		"name":    "hello \u4e16\u754c",
	}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
		Optional: []string{"name"},
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Contains(t, m["name"], "\u4e16\u754c")
}

func TestJSONFormatter_LongValues(t *testing.T) {
	f := &audit.JSONFormatter{}
	longVal := strings.Repeat("x", 64*1024) // 64KB
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": longVal,
	}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, longVal, m["outcome"])
}

func TestJSONFormatter_NilFields(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", nil, &audit.EventDef{
		Category: "write",
	})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, "ev", m["event_type"])
}

func TestJSONFormatter_NewlineInjection(t *testing.T) {
	f := &audit.JSONFormatter{}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "success\n{\"injected\":true}",
	}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)

	// The output must be a single line (one trailing newline only).
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	assert.Equal(t, 1, len(lines), "embedded newline must not produce a second line")
}

func TestJSONFormatter_ExtraFieldsSorted(t *testing.T) {
	f := &audit.JSONFormatter{OmitEmpty: false}
	data, err := f.Format(testTime, "ev", audit.Fields{
		"outcome": "ok",
		"zebra":   "z",
		"alpha":   "a",
	}, &audit.EventDef{
		Category: "write",
		Required: []string{"outcome"},
	})
	require.NoError(t, err)

	raw := string(data)
	aIdx := strings.Index(raw, `"alpha"`)
	zIdx := strings.Index(raw, `"zebra"`)
	assert.Less(t, aIdx, zIdx, "extra fields should be sorted")
}
