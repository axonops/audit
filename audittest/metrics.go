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

package audittest

import (
	"sync"
	"time"

	"github.com/axonops/audit"
)

var _ audit.Metrics = (*MetricsRecorder)(nil)

// MetricsRecorder implements [audit.Metrics] and captures all metric
// calls for assertion. It is safe for concurrent use.
//
// MetricsRecorder also satisfies the per-output metrics interfaces
// (file.Metrics, syslog.Metrics, webhook.Metrics, loki.Metrics) via
// structural typing. When passed as coreMetrics to outputconfig.Load
// via WithCoreMetrics, per-output metrics are auto-detected.
type MetricsRecorder struct { //nolint:govet // mu placed first for clarity over alignment
	mu                  sync.Mutex     // guards all fields below
	events              map[string]int // "output:status" → count
	outputErrors        map[string]int
	outputFiltered      map[string]int
	validationErrors    map[string]int
	filtered            map[string]int
	serializationErrors map[string]int
	bufferDrops         int
	submitted           int

	// Per-output metrics (satisfies file.Metrics, syslog.Metrics,
	// webhook.Metrics, loki.Metrics via structural typing).
	fileRotations    map[string]int // path → count
	syslogReconnects map[string]int // "address:success"/"address:failure" → count
	webhookDrops     int
	webhookFlushes   int
	lokiDrops        int
	lokiFlushes      int
	lokiRetries      int
	lokiErrors       int
}

// NewMetricsRecorder creates a MetricsRecorder ready for use with
// [audit.WithMetrics].
func NewMetricsRecorder() *MetricsRecorder {
	return &MetricsRecorder{
		events:              make(map[string]int),
		outputErrors:        make(map[string]int),
		outputFiltered:      make(map[string]int),
		validationErrors:    make(map[string]int),
		filtered:            make(map[string]int),
		serializationErrors: make(map[string]int),
		fileRotations:       make(map[string]int),
		syslogReconnects:    make(map[string]int),
	}
}

// --- audit.Metrics implementation ---

// RecordSubmitted implements [audit.Metrics].
func (m *MetricsRecorder) RecordSubmitted() {
	m.mu.Lock()
	m.submitted++
	m.mu.Unlock()
}

// RecordEvent implements [audit.Metrics].
func (m *MetricsRecorder) RecordEvent(output, status string) {
	m.mu.Lock()
	m.events[output+":"+status]++
	m.mu.Unlock()
}

// RecordOutputError implements [audit.Metrics].
func (m *MetricsRecorder) RecordOutputError(output string) {
	m.mu.Lock()
	m.outputErrors[output]++
	m.mu.Unlock()
}

// RecordOutputFiltered implements [audit.Metrics].
func (m *MetricsRecorder) RecordOutputFiltered(output string) {
	m.mu.Lock()
	m.outputFiltered[output]++
	m.mu.Unlock()
}

// RecordValidationError implements [audit.Metrics].
func (m *MetricsRecorder) RecordValidationError(eventType string) {
	m.mu.Lock()
	m.validationErrors[eventType]++
	m.mu.Unlock()
}

// RecordFiltered implements [audit.Metrics].
func (m *MetricsRecorder) RecordFiltered(eventType string) {
	m.mu.Lock()
	m.filtered[eventType]++
	m.mu.Unlock()
}

// RecordSerializationError implements [audit.Metrics].
func (m *MetricsRecorder) RecordSerializationError(eventType string) {
	m.mu.Lock()
	m.serializationErrors[eventType]++
	m.mu.Unlock()
}

// RecordBufferDrop implements [audit.Metrics].
func (m *MetricsRecorder) RecordBufferDrop() {
	m.mu.Lock()
	m.bufferDrops++
	m.mu.Unlock()
}

// RecordQueueDepth implements [audit.Metrics].
func (m *MetricsRecorder) RecordQueueDepth(_, _ int) {}

// --- Query methods ---

// EventDeliveries returns the number of delivery attempts recorded
// for the given output and status ("success" or "error").
func (m *MetricsRecorder) EventDeliveries(output, status string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events[output+":"+status]
}

// ValidationErrors returns the count of validation errors recorded
// for the given event type.
func (m *MetricsRecorder) ValidationErrors(eventType string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.validationErrors[eventType]
}

// FilteredCount returns the count of globally filtered events for
// the given event type.
func (m *MetricsRecorder) FilteredCount(eventType string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.filtered[eventType]
}

// BufferDrops returns the total number of buffer-full drops.
func (m *MetricsRecorder) BufferDrops() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bufferDrops
}

// OutputErrors returns the count of write errors for the given output.
func (m *MetricsRecorder) OutputErrors(output string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.outputErrors[output]
}

// OutputFiltered returns the count of per-output route-filtered events.
func (m *MetricsRecorder) OutputFiltered(output string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.outputFiltered[output]
}

// SerializationErrors returns the count of serialisation errors for
// the given event type.
func (m *MetricsRecorder) SerializationErrors(eventType string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.serializationErrors[eventType]
}

// --- Per-output metrics (structural typing) ---

// RecordFileRotation satisfies file.Metrics.
func (m *MetricsRecorder) RecordFileRotation(path string) {
	m.mu.Lock()
	m.fileRotations[path]++
	m.mu.Unlock()
}

// RecordSyslogReconnect satisfies syslog.Metrics.
func (m *MetricsRecorder) RecordSyslogReconnect(address string, success bool) {
	key := address + ":failure"
	if success {
		key = address + ":success"
	}
	m.mu.Lock()
	m.syslogReconnects[key]++
	m.mu.Unlock()
}

// RecordWebhookDrop satisfies webhook.Metrics.
func (m *MetricsRecorder) RecordWebhookDrop() {
	m.mu.Lock()
	m.webhookDrops++
	m.mu.Unlock()
}

// RecordWebhookFlush satisfies webhook.Metrics.
func (m *MetricsRecorder) RecordWebhookFlush(_ int, _ time.Duration) {
	m.mu.Lock()
	m.webhookFlushes++
	m.mu.Unlock()
}

// RecordLokiDrop satisfies loki.Metrics.
func (m *MetricsRecorder) RecordLokiDrop() {
	m.mu.Lock()
	m.lokiDrops++
	m.mu.Unlock()
}

// RecordLokiFlush satisfies loki.Metrics.
func (m *MetricsRecorder) RecordLokiFlush(_ int, _ time.Duration) {
	m.mu.Lock()
	m.lokiFlushes++
	m.mu.Unlock()
}

// RecordLokiRetry satisfies loki.Metrics.
func (m *MetricsRecorder) RecordLokiRetry(_, _ int) {
	m.mu.Lock()
	m.lokiRetries++
	m.mu.Unlock()
}

// RecordLokiError satisfies loki.Metrics.
func (m *MetricsRecorder) RecordLokiError(_ int) {
	m.mu.Lock()
	m.lokiErrors++
	m.mu.Unlock()
}

// --- Per-output query methods ---

// FileRotations returns the count of file rotations for the given path.
func (m *MetricsRecorder) FileRotations(path string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fileRotations[path]
}

// SyslogReconnects returns the count of syslog reconnections for the
// given address and outcome.
func (m *MetricsRecorder) SyslogReconnects(address string, success bool) int {
	key := address + ":failure"
	if success {
		key = address + ":success"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syslogReconnects[key]
}

// WebhookDrops returns the total count of webhook event drops.
func (m *MetricsRecorder) WebhookDrops() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.webhookDrops
}

// WebhookFlushes returns the total count of webhook batch flushes.
func (m *MetricsRecorder) WebhookFlushes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.webhookFlushes
}

// LokiDrops returns the total count of Loki event drops.
func (m *MetricsRecorder) LokiDrops() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lokiDrops
}

// LokiFlushes returns the total count of Loki batch flushes.
func (m *MetricsRecorder) LokiFlushes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lokiFlushes
}

// LokiRetries returns the total count of Loki push retries.
func (m *MetricsRecorder) LokiRetries() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lokiRetries
}

// LokiErrors returns the total count of Loki push errors.
func (m *MetricsRecorder) LokiErrors() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lokiErrors
}

// Reset clears all recorded metrics.
func (m *MetricsRecorder) Reset() {
	m.mu.Lock()
	m.events = make(map[string]int)
	m.outputErrors = make(map[string]int)
	m.outputFiltered = make(map[string]int)
	m.validationErrors = make(map[string]int)
	m.filtered = make(map[string]int)
	m.serializationErrors = make(map[string]int)
	m.fileRotations = make(map[string]int)
	m.syslogReconnects = make(map[string]int)
	m.bufferDrops = 0
	m.webhookDrops = 0
	m.webhookFlushes = 0
	m.lokiDrops = 0
	m.lokiFlushes = 0
	m.lokiRetries = 0
	m.lokiErrors = 0
	m.mu.Unlock()
}
