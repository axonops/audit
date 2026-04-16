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

package audittest_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

func TestRecorder_Write(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	err := rec.Write([]byte(`{"timestamp":"2026-01-01T00:00:00Z","event_type":"user_create","severity":5,"actor_id":"alice","outcome":"success"}` + "\n"))
	require.NoError(t, err)

	events := rec.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "user_create", events[0].EventType)
	assert.Equal(t, 5, events[0].Severity)
	assert.Equal(t, "alice", events[0].Fields["actor_id"])
	assert.Equal(t, "success", events[0].Fields["outcome"])
	assert.NotEmpty(t, events[0].RawJSON)
}

func TestRecorder_FindByType(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	_ = rec.Write([]byte(`{"event_type":"user_create","severity":5}` + "\n"))
	_ = rec.Write([]byte(`{"event_type":"auth_failure","severity":8}` + "\n"))
	_ = rec.Write([]byte(`{"event_type":"user_create","severity":5}` + "\n"))

	found := rec.FindByType("user_create")
	assert.Len(t, found, 2)

	found = rec.FindByType("auth_failure")
	assert.Len(t, found, 1)

	found = rec.FindByType("nonexistent")
	assert.Empty(t, found)
}

func TestRecorder_Count(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	assert.Equal(t, 0, rec.Count())

	_ = rec.Write([]byte(`{"event_type":"test","severity":5}` + "\n"))
	assert.Equal(t, 1, rec.Count())
}

func TestRecorder_Reset(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	_ = rec.Write([]byte(`{"event_type":"test","severity":5}` + "\n"))
	assert.Equal(t, 1, rec.Count())

	rec.Reset()
	assert.Equal(t, 0, rec.Count())
	assert.Empty(t, rec.Events())
}

func TestRecorder_GoString(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	assert.Contains(t, rec.GoString(), "events: []")

	_ = rec.Write([]byte(`{"event_type":"user_create","severity":5}` + "\n"))
	s := rec.GoString()
	assert.Contains(t, s, "user_create")
	assert.Contains(t, s, "[0]")
}

func TestRecordedEvent_Field(t *testing.T) {
	t.Parallel()
	evt := audittest.RecordedEvent{
		Fields: map[string]any{"actor_id": "alice", "count": float64(42)},
	}
	assert.Equal(t, "alice", evt.Field("actor_id"))
	assert.Equal(t, float64(42), evt.Field("count"))
	assert.Nil(t, evt.Field("nonexistent"))
}

func TestRecordedEvent_HasField(t *testing.T) {
	t.Parallel()
	evt := audittest.RecordedEvent{
		Fields: map[string]any{"actor_id": "alice", "count": float64(42)},
	}
	assert.True(t, evt.HasField("actor_id", "alice"))
	assert.False(t, evt.HasField("actor_id", "bob"))
	assert.False(t, evt.HasField("nonexistent", "anything"))
	assert.True(t, evt.HasField("count", float64(42)))
}

func TestRecorder_Name(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	assert.Equal(t, "recorder", rec.Name())
}

func TestRecorder_Close(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	assert.NoError(t, rec.Close())
}

func TestRecorder_ConcurrentWriteAndRead(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = rec.Write([]byte(`{"event_type":"test","severity":5}` + "\n"))
			_ = rec.Count()
			_ = rec.Events()
		}()
	}
	wg.Wait()
	assert.Equal(t, 100, rec.Count())
}

// TestRecorder_FullPipeline verifies the recorder works end-to-end
// with a real audit auditor.
func TestRecorder_FullPipeline(t *testing.T) {
	t.Parallel()
	auditor, events, metrics := audittest.NewQuick(t, "user_create")

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	assert.Equal(t, "user_create", evt.EventType)
	assert.Equal(t, "alice", evt.Field("actor_id"))
	assert.True(t, evt.HasField("outcome", "success"))

	assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}

// ---------------------------------------------------------------------------
// RecordedEvent field accessors (#397)
// ---------------------------------------------------------------------------

func TestRecordedEvent_StringField(t *testing.T) {
	t.Parallel()
	evt := audittest.RecordedEvent{
		Fields: map[string]any{
			"name":  "alice",
			"count": float64(42),
		},
	}
	assert.Equal(t, "alice", evt.StringField("name"))
	assert.Equal(t, "", evt.StringField("count"), "non-string returns empty")
	assert.Equal(t, "", evt.StringField("missing"), "missing returns empty")
}

func TestRecordedEvent_IntField_CoercesFloat64(t *testing.T) {
	t.Parallel()
	evt := audittest.RecordedEvent{
		Fields: map[string]any{
			"count": float64(42), // JSON round-trip stores as float64
			"exact": 5,           // int if set directly
			"name":  "alice",
			"rate":  3.14,
		},
	}
	assert.Equal(t, 42, evt.IntField("count"), "float64 coerced to int")
	assert.Equal(t, 5, evt.IntField("exact"), "int stays int")
	assert.Equal(t, 0, evt.IntField("name"), "non-numeric returns 0")
	assert.Equal(t, 3, evt.IntField("rate"), "float64 truncates")
	assert.Equal(t, 0, evt.IntField("missing"), "missing returns 0")
}

func TestRecordedEvent_FloatField(t *testing.T) {
	t.Parallel()
	evt := audittest.RecordedEvent{
		Fields: map[string]any{
			"rate": float64(3.14),
			"name": "alice",
		},
	}
	assert.InDelta(t, 3.14, evt.FloatField("rate"), 0.001)
	assert.Equal(t, float64(0), evt.FloatField("name"), "non-float returns 0")
	assert.Equal(t, float64(0), evt.FloatField("missing"), "missing returns 0")
}

func TestRecordedEvent_UserFields(t *testing.T) {
	t.Parallel()
	evt := audittest.RecordedEvent{
		Fields: map[string]any{
			"actor_id":       "alice",
			"outcome":        "success",
			"event_category": "write",
			"app_name":       "my-app",
			"host":           "localhost",
			"timezone":       "UTC",
			"pid":            float64(1234),
			"duration_ms":    float64(10),
			"_hmac":          "abc",
			"_hmac_v":        float64(1),
		},
	}
	userFields := evt.UserFields()
	assert.Equal(t, 2, len(userFields), "only user fields remain")
	assert.Equal(t, "alice", userFields["actor_id"])
	assert.Equal(t, "success", userFields["outcome"])
	// Framework fields excluded.
	assert.NotContains(t, userFields, "event_category")
	assert.NotContains(t, userFields, "app_name")
	assert.NotContains(t, userFields, "host")
	assert.NotContains(t, userFields, "timezone")
	assert.NotContains(t, userFields, "pid")
	assert.NotContains(t, userFields, "duration_ms")
	assert.NotContains(t, userFields, "_hmac")
	assert.NotContains(t, userFields, "_hmac_v")
}

func TestRecordedEvent_BoolField(t *testing.T) {
	t.Parallel()
	evt := audittest.RecordedEvent{
		Fields: map[string]any{
			"active":  true,
			"deleted": false,
			"name":    "alice",
		},
	}
	assert.True(t, evt.BoolField("active"))
	assert.False(t, evt.BoolField("deleted"))
	assert.False(t, evt.BoolField("name"), "non-bool returns false")
	assert.False(t, evt.BoolField("missing"), "missing returns false")
}

func TestRecorder_Write_InvalidJSON(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	err := rec.Write([]byte("this is not json\n"))
	require.NoError(t, err)

	events := rec.Events()
	require.Len(t, events, 1)
	assert.Error(t, events[0].ParseErr, "ParseErr set for invalid JSON")
	assert.Empty(t, events[0].EventType, "EventType zero-valued")
	assert.Equal(t, 0, events[0].Severity, "Severity zero-valued")
	assert.True(t, events[0].Timestamp.IsZero(), "Timestamp zero-valued")
}

func TestRecorder_Timestamp_RFC3339(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	_ = rec.Write([]byte(`{"event_type":"test","timestamp":"2026-03-15T10:30:00Z"}` + "\n"))

	events := rec.Events()
	require.Len(t, events, 1)
	assert.False(t, events[0].Timestamp.IsZero(), "timestamp parsed from RFC3339")
	assert.Equal(t, 2026, events[0].Timestamp.Year())
	assert.Equal(t, 3, int(events[0].Timestamp.Month()))
	assert.Equal(t, 15, events[0].Timestamp.Day())
}

func TestRecorder_Timestamp_Float64(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	// 1710000000000 ms = some date in 2024
	_ = rec.Write([]byte(`{"event_type":"test","timestamp":1710000000000}` + "\n"))

	events := rec.Events()
	require.Len(t, events, 1)
	assert.False(t, events[0].Timestamp.IsZero(), "timestamp parsed from float64 millis")
}

func TestRecorder_Last_Empty(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	_, ok := rec.Last()
	assert.False(t, ok, "Last on empty recorder returns false")
}

func TestRecorder_First(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	_ = rec.Write([]byte(`{"event_type":"first","severity":1}` + "\n"))
	_ = rec.Write([]byte(`{"event_type":"second","severity":2}` + "\n"))

	evt, ok := rec.First()
	assert.True(t, ok)
	assert.Equal(t, "first", evt.EventType)

	last, ok := rec.Last()
	assert.True(t, ok)
	assert.Equal(t, "second", last.EventType)
}

func TestRecorder_FindByField(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	_ = rec.Write([]byte(`{"event_type":"test","severity":5,"actor_id":"alice"}` + "\n"))
	_ = rec.Write([]byte(`{"event_type":"test","severity":5,"actor_id":"bob"}` + "\n"))
	_ = rec.Write([]byte(`{"event_type":"test","severity":5,"actor_id":"alice"}` + "\n"))

	found := rec.FindByField("actor_id", "alice")
	assert.Len(t, found, 2)

	found = rec.FindByField("actor_id", "bob")
	assert.Len(t, found, 1)

	found = rec.FindByField("actor_id", "nonexistent")
	assert.Empty(t, found)
}

func TestRecorder_RequireEvent(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	_ = rec.Write([]byte(`{"event_type":"user_create","severity":5}` + "\n"))

	evt := rec.RequireEvent(t, "user_create")
	assert.Equal(t, "user_create", evt.EventType)
}

func TestRecorder_RequireEmpty(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	rec.RequireEmpty(t) // should not fail
}

func TestRecorder_AssertContains(t *testing.T) {
	t.Parallel()
	rec := audittest.NewRecorder()
	_ = rec.Write([]byte(`{"event_type":"user_create","severity":5,"actor_id":"alice","outcome":"success"}` + "\n"))
	_ = rec.Write([]byte(`{"event_type":"user_create","severity":5,"actor_id":"bob","outcome":"failure"}` + "\n"))

	// Match on alice's event.
	rec.AssertContains(t, "user_create", audit.Fields{
		"actor_id": "alice",
		"outcome":  "success",
	})

	// Match on bob's event.
	rec.AssertContains(t, "user_create", audit.Fields{
		"actor_id": "bob",
	})
}

func TestRecorder_NewNamedRecorder(t *testing.T) {
	t.Parallel()
	rec := audittest.NewNamedRecorder("custom-output")
	assert.Equal(t, "custom-output", rec.Name())
}
