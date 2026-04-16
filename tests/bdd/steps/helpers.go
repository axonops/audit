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

package steps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/axonops/audit"
)

// testHTTPClient is used for all test helper HTTP calls. The short
// timeout prevents 30s hangs when Docker infrastructure isn't running.
var testHTTPClient = &http.Client{Timeout: 2 * time.Second} //nolint:gochecknoglobals // test infrastructure

// marker generates a unique crypto-random hex string for event correlation.
func marker(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// resetWebhookReceiver calls POST /reset to clear stored events and config.
// Uses testHTTPClient (2s timeout) to avoid 30s hangs when Docker isn't up.
func resetWebhookReceiver(baseURL string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/reset", http.NoBody)
	if err != nil {
		return fmt.Errorf("webhook reset request: %w", err)
	}
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook reset: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("webhook reset: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// parseJSONLines parses newline-delimited JSON from raw bytes.
func parseJSONLines(data []byte) ([]map[string]any, error) {
	lines := strings.Split(string(data), "\n")
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("invalid JSON line: %w", err)
		}
		events = append(events, event)
	}
	return events, nil
}

// eventMatchesExactly checks that the event map contains ALL expected
// field/value pairs and NO unexpected fields (except auto-populated ones
// like timestamp). Values are compared as strings after JSON decoding.
// The allowExtra parameter lists fields that are allowed but not required
// (e.g., "timestamp" which is auto-populated).
func eventMatchesExactly(event map[string]any, expected map[string]string, allowExtra []string) (match bool, mismatch string) {
	// Check all expected fields are present with correct values.
	for field, want := range expected {
		got, exists := event[field]
		if !exists {
			return false, fmt.Sprintf("field %q not found in event", field)
		}
		gotStr := formatFieldValue(got)
		if want != gotStr {
			return false, fmt.Sprintf("field %q: want %q, got %q", field, want, gotStr)
		}
	}

	// Check no unexpected fields are present.
	allowed := make(map[string]bool, len(expected)+len(allowExtra))
	for k := range expected {
		allowed[k] = true
	}
	for _, k := range allowExtra {
		allowed[k] = true
	}
	for k := range event {
		if !allowed[k] {
			return false, fmt.Sprintf("unexpected field %q in event (value: %v)", k, event[k])
		}
	}

	return true, ""
}

// formatFieldValue converts a JSON-decoded value to a string for comparison.
// Handles float64 (JSON numbers) by formatting integers without decimal.
func formatFieldValue(v any) string {
	switch val := v.(type) {
	case float64:
		// JSON numbers decode as float64. Format integers without decimal.
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case string:
		return val
	case bool:
		if val {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", val)
	}
}

// --- Mock metrics ---

// MockMetrics captures all metrics calls for assertion in BDD steps.
// Thread-safe: the drain goroutine calls metrics methods concurrently.
type MockMetrics struct { //nolint:govet // fieldalignment: readability preferred
	Events            map[string]int // "output:status" -> count
	OutputErrors      map[string]int
	OutputFiltered    map[string]int
	ValidationErrors  map[string]int
	Filtered          map[string]int
	SerializationErrs map[string]int
	mu                sync.Mutex
	BufferDrops       int
	Submitted         int
	QueueDepths       []QueueDepthRecord
}

// QueueDepthRecord captures a single RecordQueueDepth call.
type QueueDepthRecord struct {
	Depth    int
	Capacity int
}

// NewMockMetrics creates a fresh MockMetrics.
func NewMockMetrics() *MockMetrics {
	return &MockMetrics{
		Events:            make(map[string]int),
		OutputErrors:      make(map[string]int),
		OutputFiltered:    make(map[string]int),
		ValidationErrors:  make(map[string]int),
		Filtered:          make(map[string]int),
		SerializationErrs: make(map[string]int),
	}
}

// RecordEvent satisfies audit.Metrics.
func (m *MockMetrics) RecordEvent(output, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events[output+":"+status]++
}

// RecordOutputError satisfies audit.Metrics.
func (m *MockMetrics) RecordOutputError(output string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OutputErrors[output]++
}

// RecordOutputFiltered satisfies audit.Metrics.
func (m *MockMetrics) RecordOutputFiltered(output string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OutputFiltered[output]++
}

// RecordValidationError satisfies audit.Metrics.
func (m *MockMetrics) RecordValidationError(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ValidationErrors[eventType]++
}

// RecordFiltered satisfies audit.Metrics.
func (m *MockMetrics) RecordFiltered(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Filtered[eventType]++
}

// RecordSerializationError satisfies audit.Metrics.
func (m *MockMetrics) RecordSerializationError(eventType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SerializationErrs[eventType]++
}

// RecordBufferDrop satisfies audit.Metrics.
func (m *MockMetrics) RecordBufferDrop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BufferDrops++
}

// RecordSubmitted satisfies audit.Metrics.
func (m *MockMetrics) RecordSubmitted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Submitted++
}

// RecordQueueDepth satisfies audit.Metrics.
func (m *MockMetrics) RecordQueueDepth(depth, capacity int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.QueueDepths = append(m.QueueDepths, QueueDepthRecord{Depth: depth, Capacity: capacity})
}

// SubmittedCount returns the number of RecordSubmitted calls.
func (m *MockMetrics) SubmittedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Submitted
}

// QueueDepthCallCount returns the number of RecordQueueDepth calls.
func (m *MockMetrics) QueueDepthCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.QueueDepths)
}

// HasSuccessEventFor returns true if any "key:success" event was recorded
// where key contains the given substring.
func (m *MockMetrics) HasSuccessEventFor(substr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.Events {
		if strings.Contains(k, substr) && strings.HasSuffix(k, ":success") && v > 0 {
			return true
		}
	}
	return false
}

// HasOutputErrorFor returns true if any output error was recorded
// where the key contains the given substring.
func (m *MockMetrics) HasOutputErrorFor(substr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.OutputErrors {
		if strings.Contains(k, substr) && v > 0 {
			return true
		}
	}
	return false
}

// --- Mock output metrics ---

// MockOutputMetrics captures all OutputMetrics calls for BDD assertion.
// Thread-safe: output writeLoop goroutines call methods concurrently.
type MockOutputMetrics struct { //nolint:govet // fieldalignment: readability preferred
	mu       sync.Mutex
	drops    int
	flushes  int
	errors   int
	retries  int
	queueDs  []QueueDepthRecord
	flushDur []time.Duration
}

// RecordDrop satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordDrop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drops++
}

// RecordFlush satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordFlush(_ int, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushes++
	m.flushDur = append(m.flushDur, dur)
}

// RecordError satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors++
}

// RecordRetry satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordRetry(_ int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retries++
}

// RecordQueueDepth satisfies audit.OutputMetrics.
func (m *MockOutputMetrics) RecordQueueDepth(depth, capacity int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueDs = append(m.queueDs, QueueDepthRecord{Depth: depth, Capacity: capacity})
}

// DropCount returns the number of drop events recorded.
func (m *MockOutputMetrics) DropCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drops
}

// FlushCount returns the number of flush events recorded.
func (m *MockOutputMetrics) FlushCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushes
}

// ErrorCount returns the number of error events recorded.
func (m *MockOutputMetrics) ErrorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errors
}

// MockOutputMetricsFactory records all factory calls and returns
// MockOutputMetrics instances keyed by "outputType:outputName".
type MockOutputMetricsFactory struct { //nolint:govet // fieldalignment: readability preferred
	mu      sync.Mutex
	Calls   []OutputMetricsFactoryCall
	Metrics map[string]*MockOutputMetrics // "type:name" -> metrics
}

// OutputMetricsFactoryCall records a single factory invocation.
type OutputMetricsFactoryCall struct {
	OutputType string
	OutputName string
}

// NewMockOutputMetricsFactory creates a factory that records calls.
func NewMockOutputMetricsFactory() *MockOutputMetricsFactory {
	return &MockOutputMetricsFactory{
		Metrics: make(map[string]*MockOutputMetrics),
	}
}

// Factory returns the audit.OutputMetricsFactory function.
func (f *MockOutputMetricsFactory) Factory() audit.OutputMetricsFactory {
	return func(outputType, outputName string) audit.OutputMetrics {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.Calls = append(f.Calls, OutputMetricsFactoryCall{
			OutputType: outputType,
			OutputName: outputName,
		})
		m := &MockOutputMetrics{}
		f.Metrics[outputType+":"+outputName] = m
		return m
	}
}

// CallCount returns the number of times the factory was invoked.
func (f *MockOutputMetricsFactory) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Calls)
}

// WasCalledWith returns true if the factory was called with the given
// outputType and outputName.
func (f *MockOutputMetricsFactory) WasCalledWith(outputType, outputName string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range f.Calls {
		if call.OutputType == outputType && call.OutputName == outputName {
			return true
		}
	}
	return false
}

// GetCalls returns a snapshot of all factory calls.
func (f *MockOutputMetricsFactory) GetCalls() []OutputMetricsFactoryCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]OutputMetricsFactoryCall, len(f.Calls))
	copy(cp, f.Calls)
	return cp
}

// MetricsFor returns the MockOutputMetrics created for the given key.
func (f *MockOutputMetricsFactory) MetricsFor(outputType, outputName string) *MockOutputMetrics {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Metrics[outputType+":"+outputName]
}
