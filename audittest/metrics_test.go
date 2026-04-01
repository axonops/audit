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

	"github.com/axonops/go-audit/audittest"
)

func TestMetricsRecorder_AllMethods(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	m.RecordEvent("recorder", "success")
	m.RecordEvent("recorder", "success")
	m.RecordEvent("recorder", "error")
	m.RecordOutputError("recorder")
	m.RecordOutputFiltered("recorder")
	m.RecordValidationError("user_create")
	m.RecordFiltered("user_read")
	m.RecordSerializationError("bad_event")
	m.RecordBufferDrop()
	m.RecordBufferDrop()

	assert.Equal(t, 2, m.EventDeliveries("recorder", "success"))
	assert.Equal(t, 1, m.EventDeliveries("recorder", "error"))
	assert.Equal(t, 1, m.OutputErrors("recorder"))
	assert.Equal(t, 1, m.OutputFiltered("recorder"))
	assert.Equal(t, 1, m.ValidationErrors("user_create"))
	assert.Equal(t, 1, m.FilteredCount("user_read"))
	assert.Equal(t, 1, m.SerializationErrors("bad_event"))
	assert.Equal(t, 2, m.BufferDrops())
}

func TestMetricsRecorder_ZeroValues(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	assert.Equal(t, 0, m.EventDeliveries("unknown", "success"))
	assert.Equal(t, 0, m.ValidationErrors("unknown"))
	assert.Equal(t, 0, m.BufferDrops())
}

func TestMetricsRecorder_Reset(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	m.RecordEvent("recorder", "success")
	m.RecordBufferDrop()
	m.RecordValidationError("test")

	m.Reset()

	assert.Equal(t, 0, m.EventDeliveries("recorder", "success"))
	assert.Equal(t, 0, m.BufferDrops())
	assert.Equal(t, 0, m.ValidationErrors("test"))
}
