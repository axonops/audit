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

var _ audit.OutputMetrics = (*OutputMetricsRecorder)(nil)

// OutputMetricsRecorder implements [audit.OutputMetrics] and captures
// all per-output metric calls for assertion. Use with
// [audit.OutputMetricsReceiver.SetOutputMetrics] when testing custom
// outputs. It is safe for concurrent use.
type OutputMetricsRecorder struct { //nolint:govet // fieldalignment: readability preferred
	mu       sync.Mutex
	drops    int
	flushes  int
	errors   int
	retries  int
	flushDur []time.Duration
}

// NewOutputMetricsRecorder creates an OutputMetricsRecorder.
func NewOutputMetricsRecorder() *OutputMetricsRecorder {
	return &OutputMetricsRecorder{}
}

// RecordDrop implements [audit.OutputMetrics].
func (m *OutputMetricsRecorder) RecordDrop() { m.mu.Lock(); m.drops++; m.mu.Unlock() }

// RecordFlush implements [audit.OutputMetrics].
func (m *OutputMetricsRecorder) RecordFlush(_ int, d time.Duration) {
	m.mu.Lock()
	m.flushes++
	m.flushDur = append(m.flushDur, d)
	m.mu.Unlock()
}

// RecordError implements [audit.OutputMetrics].
func (m *OutputMetricsRecorder) RecordError() { m.mu.Lock(); m.errors++; m.mu.Unlock() }

// RecordRetry implements [audit.OutputMetrics].
func (m *OutputMetricsRecorder) RecordRetry(_ int) { m.mu.Lock(); m.retries++; m.mu.Unlock() }

// RecordQueueDepth implements [audit.OutputMetrics].
func (m *OutputMetricsRecorder) RecordQueueDepth(_, _ int) {}

// DropCount returns the number of recorded drops.
func (m *OutputMetricsRecorder) DropCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drops
}

// FlushCount returns the number of recorded flushes.
func (m *OutputMetricsRecorder) FlushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushes
}

// ErrorCount returns the number of recorded errors.
func (m *OutputMetricsRecorder) ErrorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errors
}

// RetryCount returns the number of recorded retries.
func (m *OutputMetricsRecorder) RetryCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.retries
}

// Reset clears all recorded output metrics.
func (m *OutputMetricsRecorder) Reset() {
	m.mu.Lock()
	m.drops = 0
	m.flushes = 0
	m.errors = 0
	m.retries = 0
	m.flushDur = nil
	m.mu.Unlock()
}
