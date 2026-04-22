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

	"github.com/axonops/audit/audittest"
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

func TestMetricsRecorder_PerOutputMetrics(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	// File metrics.
	m.RecordRotation("/var/log/audit.log")
	m.RecordRotation("/var/log/audit.log")
	assert.Equal(t, 2, m.FileRotations("/var/log/audit.log"))
	assert.Equal(t, 0, m.FileRotations("/other/path"))

	// Syslog metrics.
	m.RecordReconnect("localhost:514", true)
	m.RecordReconnect("localhost:514", false)
	m.RecordReconnect("localhost:514", false)
	assert.Equal(t, 1, m.SyslogReconnects("localhost:514", true))
	assert.Equal(t, 2, m.SyslogReconnects("localhost:514", false))

	// Webhook metrics.
	// Per-output metrics (webhook/loki) are now handled via
	// audit.OutputMetrics and OutputMetricsReceiver — see #455.
}

func TestMetricsRecorder_PerOutputMetrics_ZeroValues(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	assert.Equal(t, 0, m.FileRotations("/any"))
	assert.Equal(t, 0, m.SyslogReconnects("any", true))
}

func TestMetricsRecorder_Reset(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	// Core metrics.
	m.RecordEvent("recorder", "success")
	m.RecordBufferDrop()
	m.RecordValidationError("test")

	// Per-output extension metrics.
	m.RecordRotation("/path")
	m.RecordReconnect("addr", true)

	m.Reset()

	// Core zeroed.
	assert.Equal(t, 0, m.EventDeliveries("recorder", "success"))
	assert.Equal(t, 0, m.BufferDrops())
	assert.Equal(t, 0, m.ValidationErrors("test"))

	// Per-output extension zeroed.
	assert.Equal(t, 0, m.FileRotations("/path"))
	assert.Equal(t, 0, m.SyslogReconnects("addr", true))
}

func TestMetricsRecorder_SubmittedCount(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	assert.Equal(t, 0, m.SubmittedCount())
	m.RecordSubmitted()
	m.RecordSubmitted()
	m.RecordSubmitted()
	assert.Equal(t, 3, m.SubmittedCount())
}

func TestMetricsRecorder_Reset_AllFields(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	// Populate all 10 metric fields.
	m.RecordSubmitted()
	m.RecordEvent("out", "success")
	m.RecordOutputError("out")
	m.RecordOutputFiltered("out")
	m.RecordValidationError("evt")
	m.RecordFiltered("evt")
	m.RecordSerializationError("evt")
	m.RecordBufferDrop()
	m.RecordRotation("/path")
	m.RecordReconnect("addr", true)

	m.Reset()

	assert.Equal(t, 0, m.SubmittedCount())
	assert.Equal(t, 0, m.EventDeliveries("out", "success"))
	assert.Equal(t, 0, m.OutputErrors("out"))
	assert.Equal(t, 0, m.OutputFiltered("out"))
	assert.Equal(t, 0, m.ValidationErrors("evt"))
	assert.Equal(t, 0, m.FilteredCount("evt"))
	assert.Equal(t, 0, m.SerializationErrors("evt"))
	assert.Equal(t, 0, m.BufferDrops())
	assert.Equal(t, 0, m.FileRotations("/path"))
	assert.Equal(t, 0, m.SyslogReconnects("addr", true))
}

func TestMetricsRecorder_Concurrent(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.RecordSubmitted()
			m.RecordEvent("out", "success")
			m.RecordOutputError("out")
			m.RecordBufferDrop()
			_ = m.SubmittedCount()
			_ = m.EventDeliveries("out", "success")
			_ = m.BufferDrops()
		}()
	}
	wg.Wait()

	assert.Equal(t, 100, m.SubmittedCount())
	assert.Equal(t, 100, m.EventDeliveries("out", "success"))
	assert.Equal(t, 100, m.OutputErrors("out"))
	assert.Equal(t, 100, m.BufferDrops())
}
