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

package testhelper

import (
	"sync"
	"time"

	"github.com/axonops/go-audit"
)

// Compile-time assertion: MockMetrics satisfies audit.Metrics.
var _ audit.Metrics = (*MockMetrics)(nil)

// MockMetrics is a thread-safe mock that satisfies [audit.Metrics] and
// structurally satisfies the output-specific metrics interfaces
// (file.Metrics, syslog.Metrics, webhook.Metrics) without importing
// those packages.
type MockMetrics struct {
	Events              map[string]int // "output:status" -> count
	OutputErrors        map[string]int
	FilteredCount       map[string]int
	ValidationErrors    map[string]int // eventType -> count
	GlobalFiltered      map[string]int // eventType -> count
	SerializationErrors map[string]int // eventType -> count
	FileRotations       map[string]int // path -> count
	SyslogReconnects    map[string]int // "address:success|failure" -> count
	Mu                  sync.Mutex
	BufferDrops         int
	WebhookDrops        int
}

// NewMockMetrics creates a ready-to-use MockMetrics.
func NewMockMetrics() *MockMetrics {
	return &MockMetrics{
		Events:              make(map[string]int),
		OutputErrors:        make(map[string]int),
		FileRotations:       make(map[string]int),
		SyslogReconnects:    make(map[string]int),
		FilteredCount:       make(map[string]int),
		ValidationErrors:    make(map[string]int),
		GlobalFiltered:      make(map[string]int),
		SerializationErrors: make(map[string]int),
	}
}

// --- audit.Metrics methods ---

func (m *MockMetrics) RecordEvent(output, status string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Events[output+":"+status]++
}

func (m *MockMetrics) RecordOutputError(output string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.OutputErrors[output]++
}

func (m *MockMetrics) RecordOutputFiltered(output string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.FilteredCount[output]++
}

func (m *MockMetrics) RecordBufferDrop() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.BufferDrops++
}

func (m *MockMetrics) RecordValidationError(eventType string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.ValidationErrors[eventType]++
}

func (m *MockMetrics) RecordFiltered(eventType string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.GlobalFiltered[eventType]++
}

func (m *MockMetrics) RecordSerializationError(eventType string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.SerializationErrors[eventType]++
}

// --- webhook.Metrics methods (structural satisfaction) ---

func (m *MockMetrics) RecordWebhookDrop() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.WebhookDrops++
}

func (m *MockMetrics) RecordWebhookFlush(_ int, _ time.Duration) {}

// --- file.Metrics methods (structural satisfaction) ---

func (m *MockMetrics) RecordFileRotation(path string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.FileRotations[path]++
}

// --- syslog.Metrics methods (structural satisfaction) ---

func (m *MockMetrics) RecordSyslogReconnect(address string, success bool) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	key := address + ":"
	if success {
		key += "success"
	} else {
		key += "failure"
	}
	m.SyslogReconnects[key]++
}

// --- Accessors ---

// GetOutputFiltered returns the count of filtered events for the named output.
func (m *MockMetrics) GetOutputFiltered(output string) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.FilteredCount[output]
}

// GetEventCount returns the count of events for the named output and status.
func (m *MockMetrics) GetEventCount(output, status string) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.Events[output+":"+status]
}

// GetWebhookDrops returns the total number of webhook drops recorded.
func (m *MockMetrics) GetWebhookDrops() int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.WebhookDrops
}

// GetBufferDrops returns the total number of buffer drops recorded.
func (m *MockMetrics) GetBufferDrops() int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.BufferDrops
}

// GetSyslogReconnectCount returns the reconnect count for the given address and outcome.
func (m *MockMetrics) GetSyslogReconnectCount(address string, success bool) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	key := address + ":"
	if success {
		key += "success"
	} else {
		key += "failure"
	}
	return m.SyslogReconnects[key]
}

// GetFileRotationCount returns the rotation count for the given path.
func (m *MockMetrics) GetFileRotationCount(path string) int {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	return m.FileRotations[path]
}
