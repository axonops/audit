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

	audit "github.com/axonops/go-audit"
)

var _ audit.Metrics = (*MetricsRecorder)(nil)

// MetricsRecorder implements [audit.Metrics] and captures all metric
// calls for assertion. It is safe for concurrent use.
type MetricsRecorder struct { //nolint:govet // mu placed first for clarity over alignment
	mu                  sync.Mutex     // guards all fields below
	events              map[string]int // "output:status" → count
	outputErrors        map[string]int
	outputFiltered      map[string]int
	validationErrors    map[string]int
	filtered            map[string]int
	serializationErrors map[string]int
	bufferDrops         int
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
	}
}

// --- audit.Metrics implementation ---

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

// Reset clears all recorded metrics.
func (m *MetricsRecorder) Reset() {
	m.mu.Lock()
	m.events = make(map[string]int)
	m.outputErrors = make(map[string]int)
	m.outputFiltered = make(map[string]int)
	m.validationErrors = make(map[string]int)
	m.filtered = make(map[string]int)
	m.serializationErrors = make(map[string]int)
	m.bufferDrops = 0
	m.mu.Unlock()
}
