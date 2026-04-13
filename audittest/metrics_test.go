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
	"time"

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
	m.RecordFileRotation("/var/log/audit.log")
	m.RecordFileRotation("/var/log/audit.log")
	assert.Equal(t, 2, m.FileRotations("/var/log/audit.log"))
	assert.Equal(t, 0, m.FileRotations("/other/path"))

	// Syslog metrics.
	m.RecordSyslogReconnect("localhost:514", true)
	m.RecordSyslogReconnect("localhost:514", false)
	m.RecordSyslogReconnect("localhost:514", false)
	assert.Equal(t, 1, m.SyslogReconnects("localhost:514", true))
	assert.Equal(t, 2, m.SyslogReconnects("localhost:514", false))

	// Webhook metrics.
	m.RecordWebhookDrop()
	m.RecordWebhookDrop()
	m.RecordWebhookFlush(50, 100*time.Millisecond)
	assert.Equal(t, 2, m.WebhookDrops())
	assert.Equal(t, 1, m.WebhookFlushes())

	// Loki metrics.
	m.RecordLokiDrop()
	m.RecordLokiFlush(100, 200*time.Millisecond)
	m.RecordLokiFlush(50, 100*time.Millisecond)
	m.RecordLokiRetry(429, 1)
	m.RecordLokiError(400)
	assert.Equal(t, 1, m.LokiDrops())
	assert.Equal(t, 2, m.LokiFlushes())
	assert.Equal(t, 1, m.LokiRetries())
	assert.Equal(t, 1, m.LokiErrors())
}

func TestMetricsRecorder_PerOutputMetrics_ZeroValues(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	assert.Equal(t, 0, m.FileRotations("/any"))
	assert.Equal(t, 0, m.SyslogReconnects("any", true))
	assert.Equal(t, 0, m.WebhookDrops())
	assert.Equal(t, 0, m.WebhookFlushes())
	assert.Equal(t, 0, m.LokiDrops())
	assert.Equal(t, 0, m.LokiFlushes())
	assert.Equal(t, 0, m.LokiRetries())
	assert.Equal(t, 0, m.LokiErrors())
}

func TestMetricsRecorder_Reset(t *testing.T) {
	t.Parallel()
	m := audittest.NewMetricsRecorder()

	// Core metrics.
	m.RecordEvent("recorder", "success")
	m.RecordBufferDrop()
	m.RecordValidationError("test")

	// Per-output metrics.
	m.RecordFileRotation("/path")
	m.RecordSyslogReconnect("addr", true)
	m.RecordWebhookDrop()
	m.RecordWebhookFlush(10, time.Millisecond)
	m.RecordLokiDrop()
	m.RecordLokiFlush(10, time.Millisecond)
	m.RecordLokiRetry(429, 1)
	m.RecordLokiError(400)

	m.Reset()

	// Core zeroed.
	assert.Equal(t, 0, m.EventDeliveries("recorder", "success"))
	assert.Equal(t, 0, m.BufferDrops())
	assert.Equal(t, 0, m.ValidationErrors("test"))

	// Per-output zeroed.
	assert.Equal(t, 0, m.FileRotations("/path"))
	assert.Equal(t, 0, m.SyslogReconnects("addr", true))
	assert.Equal(t, 0, m.WebhookDrops())
	assert.Equal(t, 0, m.WebhookFlushes())
	assert.Equal(t, 0, m.LokiDrops())
	assert.Equal(t, 0, m.LokiFlushes())
	assert.Equal(t, 0, m.LokiRetries())
	assert.Equal(t, 0, m.LokiErrors())
}
