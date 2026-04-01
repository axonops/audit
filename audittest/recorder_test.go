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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/audittest"
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

// TestRecorder_FullPipeline verifies the recorder works end-to-end
// with a real audit logger.
func TestRecorder_FullPipeline(t *testing.T) {
	t.Parallel()
	logger, events, metrics := audittest.NewLoggerQuick(t, "user_create")

	err := logger.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, logger.Close())

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	assert.Equal(t, "user_create", evt.EventType)
	assert.Equal(t, "alice", evt.Field("actor_id"))
	assert.True(t, evt.HasField("outcome", "success"))

	assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}
